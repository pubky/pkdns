use std::{collections::{btree_map, BTreeMap}, fmt, sync::Arc};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{domain::{IntoLabel, Label}, rdata::SOA, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey},
    serialize::binary::BinDecodable
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest, UpdateResult, ZoneType,
    },
    server::RequestInfo, store::in_memory::InMemoryAuthority
};
use pkarr::{PkarrClient, PkarrClientAsync, PublicKey, Settings, SignedPacket};
use tracing::{debug, info, trace};


#[derive()]
pub struct PkarrAuthority {
    serial: u32,
    origins: Vec<Name>,
    first_origin: LowerName,
    pkarr: PkarrClientAsync,
}

impl PkarrAuthority {
    pub async fn new() -> Self {
        let tld = Name::from_str_relaxed("p2p").unwrap();
        let first_origin = LowerName::from(&tld);
        Self {
            origins: vec![tld],
            serial: 999,
            first_origin,
            pkarr: PkarrClient::new(Settings::default()).unwrap().as_async()
        }
    }

    pub fn origins(&self) -> impl Iterator<Item = &Name> {
        self.origins.iter()
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn top_level_domain(&self) -> &LowerName {
        &self.first_origin
    }

    /**
     * Create tld (.p2p) zone with SOA entry only
     */
    fn create_tld_mem_authority(&self) -> InMemoryAuthority {
        let mut output: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
        let first_origin = Name::from(self.first_origin.clone());
        
        // tld (.p2p) soa entry
        let soakey = RrKey::new(LowerName::from(first_origin.clone()), RecordType::SOA);
        let soa = SOA::new(first_origin.clone(), Name::from_str_relaxed("").unwrap(), 998, 999, 999, 999, 1);
        let mut set = RecordSet::new(&first_origin, RecordType::SOA, 998);
        set.add_rdata(RData::SOA(soa));
        output.insert(soakey, set);
    
        InMemoryAuthority::new(first_origin, output, ZoneType::Primary, true).unwrap()
    }

    /**
     * Add pkarr records to zone.
     */
    fn add_pkarr_records_to_mem_authority(
        &self,
        signed_packet: &SignedPacket,
        mut auth: InMemoryAuthority,
    ) -> std::result::Result<InMemoryAuthority, anyhow::Error> {
        let first_origin = Name::from(self.first_origin.clone());
    
        let mut message = signed_packet_to_hickory_message(signed_packet)?;
        let answers = message.take_answers();
    
        for mut record in answers.into_iter() {
            // disallow SOA
            if matches!(record.record_type(), RecordType::SOA) {
                continue;
            }
            // expect the z32 encoded pubkey as root name
            let name = record.name();
            if name.num_labels() < 1 {
                continue;
            }
    
            let full_name = name.clone().append_name(&first_origin).unwrap();
            record.set_name(full_name.clone());
    
            auth.upsert_mut(record, self.serial);
        };
    
        Ok(auth)
    }

    pub async fn build_mem_authority(&self, name: Name) -> InMemoryAuthority {
        let tld = Name::from(self.first_origin.clone());
        let auth = self.create_tld_mem_authority();

        match parse_name_as_pkarr_with_tld(name.clone(), &Name::from_str_relaxed(tld.clone().to_string()).unwrap()) {
            Err(err) => {
                println!("{name} not in a pkarr name format");
                return auth
            }
            Ok((remaining_name, pubkey, origin)) => {
                println!("Parsed remain={remaining_name} pubkey={pubkey} tld={origin}");
                let result = self.pkarr.resolve(&pubkey).await;
                if result.is_err() {
                    println!("Failed to pull pkarr record for {name}");
                    return auth
                }
                match result.unwrap() {
                    Some(signed_packet) => {
                        println!("{name} pkarr package found");
                        let auth = self.add_pkarr_records_to_mem_authority(&signed_packet, auth).unwrap();
                        return auth
                    }
                    None => {
                        println!("{name} no pkarr package");
                        return auth
                    },
                }
            }
        }
        // if let Ok((name, pubkey, origin)) = parse_name_as_pkarr_with_tld(name, &Name::from_str_relaxed(tld.clone().to_string()).unwrap()) {
        //     println!("{name} {pubkey} {origin} is a pkarr key!");
                
        //     match self.pkarr.resolve(&pubkey).await.map_err(err_refused)?
        //     {
        //         Some(signed_packet) => {
        //             let in_mem_auth = self.pkarr_to_in_mem_authority(&signed_packet, self.origin_name()).unwrap();
        //             println!("Lookup {original_name}");
        //             let result = in_mem_auth.lookup(&original_name, record_type, lookup_options).await;
        //             if result.is_ok() {
        //                 let lookup = result.unwrap();
        //                 println!("Lookup result {:?}", lookup);
        //                 return Ok(lookup);
        //             } else {
        //                 let err = result.unwrap_err();
        //                 println!("Lookup error {:?}", err);
        //                 return Err(err);
        //             }
        //         }
        //         None => Err(err_nx_domain("not found")),
        //     }
        // };
    
    }

}

impl PkarrAuthority {
    fn origin_name(&self) -> Name {
        Name::from_str_relaxed(self.first_origin.to_string()).unwrap()
    }
}

#[async_trait]
impl Authority for PkarrAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.first_origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        println!("{:?} {name} lookup in pkarr authority", record_type);
        let name2 = Name::from(name.clone());
        let original_name = name.clone();
        let auth = self.build_mem_authority(name2).await;

        let result = auth.lookup(&original_name, record_type, lookup_options).await;
        if result.is_ok() {
            let lookup = result.unwrap();
            println!("Lookup result {:?}", lookup);
            return Ok(lookup);
        } else {
            let err = result.unwrap_err();
            println!("Lookup error {:?}", err);
            return Err(err);
        }

        // match parse_name_as_pkarr_with_tld(name, &Name::from_str_relaxed(self.first_origin.clone().to_string()).unwrap()) {
        //     Err(err) => {
        //         println!("{name} not a pkarr name, resolve in static authority");
        //         Err(err_nx_domain("not found"))
        //     }
        //     Ok((name, pubkey, origin)) => {
        //         println!("{name} {pubkey} {origin} resolve in pkarr zones");
                
        //         match self.pkarr.resolve(&pubkey).await.map_err(err_refused)?
        //         {
        //             Some(signed_packet) => {
        //                 let in_mem_auth = pkarr_to_in_mem_authority(&signed_packet, self.origin_name()).unwrap();
        //                 println!("Lookup {original_name}");
        //                 let result = in_mem_auth.lookup(&original_name, record_type, lookup_options).await;
        //                 if result.is_ok() {
        //                     let lookup = result.unwrap();
        //                     println!("Lookup result {:?}", lookup);
        //                     return Ok(lookup);
        //                 } else {
        //                     let err = result.unwrap_err();
        //                     println!("Lookup error {:?}", err);
        //                     return Err(err);
        //                 }
        //             }
        //             None => Err(err_nx_domain("not found")),
        //         }
        //     }
        // }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        debug!("search in node authority for {}", request_info.query);
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();
        match record_type {
            RecordType::AXFR => Err(LookupError::from(ResponseCode::Refused)),
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(AuthLookup::default())
    }
}

fn parse_name_as_pkarr_with_tld(
    name: impl Into<Name>,
    tld: &Name,
) -> Result<(Name, PublicKey, Name)> {
    let name = name.into();
    println!("try pkarr parsing name={name} origin={tld}");
    if !tld.zone_of(&name) {
        println!("Not in pkarr zone");
    }
    if name.num_labels() == 1 {
        println!("Not tld (.p2p) subdomain");
    }

    let labels = name.iter().rev();
    let mut labels_without_origin = labels.skip(tld.num_labels() as usize);
    let pkey_label = labels_without_origin.next().with_context(|| "should have public key")?;
    let pkey_str = std::str::from_utf8(pkey_label)?;
    let pkey = PublicKey::try_from(pkey_str)?;
    let remaining_name = Name::from_labels(labels_without_origin.rev())?;
    return Ok((remaining_name, pkey, tld.clone()));
}


pub fn signed_packet_to_hickory_message(signed_packet: &SignedPacket) -> Result<Message> {
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_bytes(&encoded)?;
    Ok(message)
}


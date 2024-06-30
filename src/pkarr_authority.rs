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
        let tld = Name::from_str_relaxed("pkarr").unwrap();
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

    pub fn first_origin(&self) -> &LowerName {
        &self.first_origin
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
        println!("{name} lookup in node authority");
        let original_name = name.clone();
        match parse_name_as_pkarr_with_origin(name, &Name::from_str_relaxed(self.first_origin.clone().to_string()).unwrap()) {
            Err(err) => {
                println!("{name} not a pkarr name, resolve in static authority");
                Err(err_nx_domain("not found"))
            }
            Ok((name, pubkey, origin)) => {
                println!("{name} {pubkey} {origin} resolve in pkarr zones");
                
                match self.pkarr.resolve(&pubkey).await.map_err(err_refused)?
                {
                    Some(signed_packet) => {
                        let in_mem_auth = pkarr_to_in_mem_authority(&signed_packet, self.origin_name()).unwrap();
                        println!("Lookup {original_name}");

                        let result = in_mem_auth.lookup(&original_name, record_type, lookup_options).await;
                        return result;
                        // debug!(%origin, %pubkey, %name, "found records in pkarr zone");
                        // let rrkey = RrKey::new(name.into(), record_type);
                        // let matches = records.get(&rrkey);
                        // if matches.is_none() {
                        //     if records.len() > 0 {
                        //         println!("Name exists but not record type match.");
                        //         return Err(LookupError::NameExists);
                        //     } else {
                        //         return Err(err_nx_domain("no matches"));
                        //     };
                        // };
                        // let records = matches.unwrap();
                        // let new_origin = Name::parse(&pubkey.to_z32(), Some(&origin)).map_err(err_refused)?;

                        // let record_set =
                        //     record_set_append_origin(records, &new_origin, self.serial()).map_err(err_refused)?;
                            
                        // let records = LookupRecords::new(lookup_options, Arc::new(record_set));
                        
                        // let answers = AuthLookup::answers(records, None);
                        // println!("Found answers!");
                        // Ok(answers)
                    }
                    None => Err(err_nx_domain("not found")),
                }
            }
        }
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

fn parse_name_as_pkarr_with_origin(
    name: impl Into<Name>,
    origin: &Name,
) -> Result<(Name, PublicKey, Name)> {
    let name = name.into();
    println!("try pkarr parsing {origin}");
    if !origin.zone_of(&name) {
        bail!("Not in pkarr zone");
    }
    if name.num_labels() == 1 {
        bail!("Not pkarr subdomain");
    }
    let labels = name.iter().rev();
    let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
    let pkey_label = labels_without_origin.next().with_context(|| "should have public key")?;
    let pkey_str = std::str::from_utf8(pkey_label)?;
    let pkey = PublicKey::try_from(pkey_str)?;
    let remaining_name = Name::from_labels(labels_without_origin.rev())?;
    return Ok((remaining_name, pkey, origin.clone()));
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}

pub fn signed_packet_to_hickory_message(signed_packet: &SignedPacket) -> Result<Message> {
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_bytes(&encoded)?;
    Ok(message)
}

pub fn pkarr_to_in_mem_authority(
    signed_packet: &SignedPacket,
    first_origin: Name
) -> Result<InMemoryAuthority> {
    let pubkey = Label::from_utf8(&signed_packet.public_key().to_z32())?;
    let zone = Name::from_labels(vec![pubkey.clone()])?.clone().append_name(&first_origin)?.append_label(".")?;

    let mut message = signed_packet_to_hickory_message(signed_packet)?;
    let answers = message.take_answers();
    let mut output: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

    let soakey = RrKey::new(LowerName::from(zone.clone()), RecordType::SOA);
    let soa = SOA::new(zone.clone(), Name::from_str_relaxed("")?, 999, 999, 999, 999, 1);
    let mut set = RecordSet::new(&zone, RecordType::SOA, 999);
    set.add_rdata(RData::SOA(soa));
    output.insert(soakey, set);

    for mut record in answers.into_iter() {
        // disallow SOA and NS records
        if matches!(record.record_type(), RecordType::SOA) {
            continue;
        }
        // expect the z32 encoded pubkey as root name
        let name = record.name();
        if name.num_labels() < 1 {
            continue;
        }

        let name_without_zone =
            Name::from_labels(name.iter().take(name.num_labels() as usize - 1))?;

        let full_name = name.clone().append_name(&first_origin).unwrap();
        record.set_name(full_name.clone());

        let lower = LowerName::from(full_name);

        let rrkey = RrKey::new(lower, record.record_type());
        output.insert(rrkey, record.into());
    }
    let mem_auth = InMemoryAuthority::new(zone, output, ZoneType::Forward, false).unwrap();
    Ok(mem_auth)
}
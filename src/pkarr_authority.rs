use std::{collections::{btree_map, BTreeMap}, fmt, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{domain::{IntoLabel, Label}, LowerName, Name, Record, RecordSet, RecordType, RrKey},
    serialize::binary::BinDecodable
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest, UpdateResult, ZoneType,
    },
    server::RequestInfo
};
use pkarr::{PkarrClient, PkarrClientAsync, PublicKey, Settings, SignedPacket};
use tracing::{debug, trace};


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
        // let tld = Name::from_str_relaxed("").unwrap();
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
        match parse_name_as_pkarr_with_origin(name, &self.origins) {
            Err(err) => {
                println!("{name} not a pkarr name, resolve in static authority");
                Err(err_nx_domain("not found"))
            }
            Ok((name, pubkey, origin)) => {
                debug!(%origin, %pubkey, %name, "resolve in pkarr zones");
                
                let result = self.pkarr.resolve(&pubkey).await.map_err(err_refused)?;
                
                match result
                {
                    Some(signed_packet) => {
                        let (_label, records) = signed_packet_to_hickory_records_without_origin(&signed_packet, |_| true).unwrap();
                        debug!(%origin, %pubkey, %name, "found records in pkarr zone");
                        let rrkey = RrKey::new(name.into(), record_type);
                        let records = records.get(&rrkey).unwrap();
                        let new_origin = Name::parse(&pubkey.to_z32(), Some(&origin)).map_err(err_refused)?;

                        let record_set =
                            record_set_append_origin(records, &new_origin, self.serial()).map_err(err_refused)?;
                        let records = LookupRecords::new(lookup_options, Arc::new(record_set));
                        let answers = AuthLookup::answers(records, None);
                        Ok(answers)
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
    allowed_origins: &[Name],
) -> Result<(Name, PublicKey, Name)> {
    let name = name.into();
    println!("resolve {name}");
    for origin in allowed_origins.iter() {
        println!("try {origin}");
        if !origin.zone_of(&name) {
            continue;
        }
        if name.num_labels() < origin.num_labels() + 1 {
            println!("not a valid pkarr name: missing pubkey");
        }
        println!("parse {origin}");
        let labels = name.iter().rev();
        let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
        let pkey_label = labels_without_origin.next().expect("length checked above");
        let pkey_str = std::str::from_utf8(pkey_label)?;
        let pkey = PublicKey::try_from(pkey_str)?;
        let remaining_name = Name::from_labels(labels_without_origin.rev())?;
        return Ok((remaining_name, pkey, origin.clone()));
    }
    println!("name does not match any allowed origin");
    Err(err_nx_domain("not found").into())
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}

pub fn record_set_append_origin(
    input: &RecordSet,
    origin: &Name,
    serial: u32,
) -> Result<RecordSet> {
    let new_name = input.name().clone().append_name(origin)?;
    let mut output = RecordSet::new(&new_name, input.record_type(), serial);
    // TODO: less clones
    for record in input.records_without_rrsigs() {
        let mut record = record.clone();
        record.set_name(new_name.clone());
        output.insert(record, serial);
    }
    Ok(output)
}

pub fn signed_packet_to_hickory_message(signed_packet: &SignedPacket) -> Result<Message> {
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_bytes(&encoded)?;
    Ok(message)
}

pub fn signed_packet_to_hickory_records_without_origin(
    signed_packet: &SignedPacket,
    filter: impl Fn(&Record) -> bool,
) -> Result<(Label, BTreeMap<RrKey, Arc<RecordSet>>)> {
    let common_zone = Label::from_utf8(&signed_packet.public_key().to_z32())?;
    let mut message = signed_packet_to_hickory_message(signed_packet)?;
    let answers = message.take_answers();
    let mut output: BTreeMap<RrKey, Arc<RecordSet>> = BTreeMap::new();
    for mut record in answers.into_iter() {
        // disallow SOA and NS records
        if matches!(record.record_type(), RecordType::SOA | RecordType::NS) {
            continue;
        }
        // expect the z32 encoded pubkey as root name
        let name = record.name();
        if name.num_labels() < 1 {
            continue;
        }
        let zone = name.iter().last().unwrap().into_label()?;
        if zone != common_zone {
            continue;
        }
        if !filter(&record) {
            continue;
        }

        let name_without_zone =
            Name::from_labels(name.iter().take(name.num_labels() as usize - 1))?;
        record.set_name(name_without_zone);

        let rrkey = RrKey::new(record.name().into(), record.record_type());
        match output.entry(rrkey) {
            btree_map::Entry::Vacant(e) => {
                let set: RecordSet = record.into();
                e.insert(Arc::new(set));
            }
            btree_map::Entry::Occupied(mut e) => {
                let set = e.get_mut();
                let serial = set.serial();
                // safe because we just created the arc and are sync iterating
                Arc::get_mut(set).unwrap().insert(record, serial);
            }
        }
    }
    Ok((common_zone, output))
}
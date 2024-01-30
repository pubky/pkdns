use pkarr::dns::{Name, Packet};
use pknames_core::resolve::resolve_standalone;
use crate::pkarr_resolver::PkarrResolver;


#[derive(Clone)]
pub struct PknamesResolver {
    pkarr: PkarrResolver,
    config_dir_path: String,
}

impl PknamesResolver {
    pub fn new(max_cache_ttl: u64, config_dir_path: &str) -> Self {
        PknamesResolver {
            pkarr: PkarrResolver::new(max_cache_ttl),
            config_dir_path: config_dir_path.to_string()
        }
    }

    /**
     * Resolve a regular pknames domain into a pkarr domain.
     * Example: `pknames.p2p` -> `pknames.p2p.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy`.
     */
    fn predict_pknames_domain(&self, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        let result = resolve_standalone(&domain, &self.config_dir_path);
        if result.is_err() {
            return Err("Neither pkarr nor pknames domain.".into());
        };

        let predictions = result.unwrap();
        let best_class = predictions.get_best_class().expect("Class should be available.");

        let best_pubkey = best_class.pubkey.clone();
        let best_pubkey = best_pubkey.replace("pk:", ""); // Just to be sure

        let full_domain = format!("{}.{}", domain, best_pubkey);
        Ok(full_domain)
    }


    pub fn resolve(&mut self, query: &Vec<u8>) -> std::prelude::v1::Result<Vec<u8>, Box<dyn std::error::Error>> {
        let original_query = Packet::parse(query)?;

        let pkarr_result = self.pkarr.resolve(&query.clone());
        if pkarr_result.is_ok() {
            return pkarr_result; // It was a pkarr hostname
        }

        let question = original_query.questions.first().unwrap();
        let domain = question.qname.to_string();
        let pkarr_domain = self.predict_pknames_domain(&domain)?;

        let qname = Name::new(&pkarr_domain).unwrap();
        let mut pkarr_query = original_query.clone();
        pkarr_query.questions[0].qname = qname;
        let pkarr_query = pkarr_query.build_bytes_vec().unwrap();
        let pkarr_reply = self.pkarr.resolve(&pkarr_query)?;
        let pkarr_reply = Packet::parse(&pkarr_reply).unwrap();

        let mut reply = original_query.clone().into_reply();
        for answer in pkarr_reply.answers.iter() {
            let mut answer = answer.clone();
            answer.name = question.qname.clone();
            reply.answers.push(answer);
        };
        Ok(reply.build_bytes_vec().unwrap())
    }
}



#[cfg(test)]
mod tests {
    use pkarr::dns::{Name, Packet, Question};

    use super::PknamesResolver;

    #[test]
    fn query_pubkey() {
        let mut pknames = PknamesResolver::new(1, "~/.pknames");

        let mut query = Packet::new_query(0);
        let name = Name::new("pknames.p2p").unwrap();
        let question = Question::new(name, pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A), pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN), false);
        query.questions.push(question);
        let query_bytes = query.build_bytes_vec().unwrap();

        let result  = pknames.resolve(&query_bytes);
        if result.is_err() {
            eprintln!("{:?}", result.unwrap_err());
            assert!(false);
            return;
        }
        assert!(result.is_ok());

        let reply = result.unwrap();
        let reply = Packet::parse(&reply).unwrap();
        println!("{:?}", reply);

    }

}

use pkarr::dns::{Name, Packet, Question, ResourceRecord};

/// Top Level Domain like .pkd with the capability
/// to remove and add the top level domain in queries/replies.
#[derive(Clone, Debug)]
pub struct TopLevelDomain(pub String);

impl TopLevelDomain {
    pub fn new(tld: String) -> Self {
        Self(tld)
    }

    pub fn label(&self) -> &str {
        &self.0
    }

    /// Checks if the query or reply contains a question that ends with a public key and the tld.
    pub fn question_ends_with_pubkey_tld(&self, packet: &Packet<'_>) -> bool {
        let question = packet.questions.first();
        if question.is_none() {
            return false;
        }
        let question = question.unwrap();
        self.name_ends_with_pubkey_tld(&question.qname)
    }

    /// Removes the top level domain from the query if it exists.
    /// Returns the new query and a flag if the tld has been removed.
    pub fn remove(&self, packet: &mut Packet<'_>) {
        let question = packet
            .questions
            .first()
            .expect("No question in query in pkarr_resolver.");
        let labels = question.qname.get_labels();

        let question_tld = labels
            .last()
            .expect("Question labels with no domain in pkarr_resolver")
            .to_string();

        if question_tld != self.0 {
            panic!(
                "Question tld {question_tld} does not match the given tld .{}",
                self.label()
            );
        }

        // let second_label = labels.get(labels.len() - 2).expect("Question should have 2 labels");
        // let parse_res: pkarr::PublicKey = parse_pkarr_uri(&second_label.to_string()).expect("Second label must be a pkarr public key");

        let slice = &labels[0..labels.len() - 1];
        let new_domain = slice
            .iter()
            .map(|label| label.to_string())
            .collect::<Vec<String>>()
            .join(".");

        let name = Name::new(&new_domain).unwrap().into_owned();
        let new_question = Question::new(name, question.qtype, question.qclass, question.unicast_response).into_owned();
        packet.questions = vec![new_question];
    }

    /// Checks if the name ends with a public key domain and the tld.
    pub fn name_ends_with_pubkey_tld(&self, name: &Name<'_>) -> bool {
        let labels = name.get_labels();
        if labels.len() < 2 {
            // Needs at least 2 labels. First: tld, second: publickey
            return false;
        }

        let question_tld = labels.last().unwrap().to_string();

        if question_tld != self.0 {
            return false;
        };

        let second_label = labels.get(labels.len() - 2).unwrap().to_string();
        let res: Result<pkarr::PublicKey, _> = second_label.try_into();
        res.is_ok()
    }

    /// Checks if the name ends with a public key domain
    pub fn name_ends_with_pubkey(&self, name: &Name<'_>) -> bool {
        let labels = name.get_labels();
        if labels.is_empty() {
            // Needs at least 2 labels. First: tld, second: publickey
            return false;
        }

        let question_tld = labels.last().unwrap().to_string();
        let res: Result<pkarr::PublicKey, _> = question_tld.try_into();
        res.is_ok()
    }

    /// Append the top level domain to the reply. Zones are stored without a tld on Mainline
    /// so we need to add it again here.
    pub fn add(&self, reply: &mut Packet<'_>) {
        // Append questions
        let mut new_questions = vec![];
        for question in reply.questions.iter() {
            if !self.name_ends_with_pubkey(&question.qname) {
                // Other question. Don't change.
                new_questions.push(question.clone());
                continue;
            };
            let original_domain = question.qname.to_string();
            let new_domain = format!("{original_domain}.{}", self.0);
            let new_name = Name::new(&new_domain).unwrap();
            let new_question =
                Question::new(new_name, question.qtype, question.qclass, question.unicast_response).into_owned();
            new_questions.push(new_question);
        }
        reply.questions = new_questions;
        // Append answers
        let mut new_answers = vec![];
        for answer in reply.answers.iter() {
            if !self.name_ends_with_pubkey(&answer.name) {
                // Other answer. Don't change.
                new_answers.push(answer.clone());
                continue;
            };
            let original_domain = answer.name.to_string();
            let new_domain = format!("{original_domain}.{}", self.0);
            let new_name = Name::new(&new_domain).unwrap();
            let new_answer = ResourceRecord::new(new_name, answer.class, answer.ttl, answer.rdata.clone()).into_owned();
            new_answers.push(new_answer);
        }
        reply.answers = new_answers;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::dns::rdata::A;

    fn create_query_with_domain(domain: &str) -> Vec<u8> {
        let name = Name::new(domain).unwrap();
        let mut query = Packet::new_query(0);
        let question = Question::new(
            name.clone(),
            pkarr::dns::QTYPE::TYPE(pkarr::dns::TYPE::A),
            pkarr::dns::QCLASS::CLASS(pkarr::dns::CLASS::IN),
            true,
        );
        query.questions.push(question);
        query.build_bytes_vec().unwrap()
    }

    fn create_reply_with_domain(domain: &str) -> Vec<u8> {
        let query = create_query_with_domain(domain);
        let mut packet = Packet::parse(&query).unwrap().into_reply();

        let rdata = pkarr::dns::rdata::RData::A(A { address: 0 });
        let answer1 = ResourceRecord::new(Name::new(domain).unwrap(), pkarr::dns::CLASS::IN, 60, rdata.clone());
        packet.answers.push(answer1);

        let answer2 = ResourceRecord::new(Name::new("example.com").unwrap(), pkarr::dns::CLASS::IN, 60, rdata);
        packet.answers.push(answer2);

        packet.build_bytes_vec().unwrap()
    }

    #[tokio::test]
    async fn is_pkarr_with_tld_valid_2_label() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_query_with_domain("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd");
        let packet = Packet::parse(&domain).unwrap();
        assert!(tld.question_ends_with_pubkey_tld(&packet));
    }

    #[tokio::test]
    async fn is_pkarr_with_tld_valid_3_label() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_query_with_domain("test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd");
        let packet = Packet::parse(&domain).unwrap();
        assert!(tld.question_ends_with_pubkey_tld(&packet));
    }

    #[tokio::test]
    async fn is_pkarr_with_tld_fail_1_label() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_query_with_domain("pkd");
        let packet = Packet::parse(&domain).unwrap();
        assert!(!tld.question_ends_with_pubkey_tld(&packet));
    }

    #[tokio::test]
    async fn is_pkarr_with_tld_fail_2_label_no_pubkey() {
        let tld = TopLevelDomain::new("nopubkey.pkd".to_string());
        let domain = create_query_with_domain("pkd");
        let packet = Packet::parse(&domain).unwrap();
        assert!(!tld.question_ends_with_pubkey_tld(&packet));
    }

    #[tokio::test]
    async fn is_pkarr_with_tld_fail_2_label_wrong_tld() {
        let tld = TopLevelDomain::new("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.wrongpkd".to_string());
        let domain = create_query_with_domain("pkd");
        let packet = Packet::parse(&domain).unwrap();
        assert!(!tld.question_ends_with_pubkey_tld(&packet));
    }

    #[tokio::test]
    async fn remove_tld_success_2_labels() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_query_with_domain("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd");
        let mut packet = Packet::parse(&domain).unwrap();
        tld.remove(&mut packet);
        // Rebuild packet from scratch
        let removed_query = packet.build_bytes_vec().unwrap();
        let packet = Packet::parse(&removed_query).unwrap();
        let question_domain = packet.questions.first().unwrap().qname.to_string();
        assert_eq!(question_domain, "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy")
    }

    #[tokio::test]
    async fn remove_tld_success_3_labels() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_query_with_domain("test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd");
        let mut packet = Packet::parse(&domain).unwrap();
        tld.remove(&mut packet);
        // Rebuild packet from scratch
        let removed_query = packet.build_bytes_vec().unwrap();
        let packet = Packet::parse(&removed_query).unwrap();
        let question_domain = packet.questions.first().unwrap().qname.to_string();
        assert_eq!(
            question_domain,
            "test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy"
        )
    }

    #[tokio::test]
    async fn add_success_1_label() {
        let tld = TopLevelDomain::new("pkd".to_string());
        let domain = create_reply_with_domain("7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy");
        let mut packet = Packet::parse(&domain).unwrap();
        tld.add(&mut packet);
        // Rebuild packet from scratch
        let removed_query = packet.build_bytes_vec().unwrap();
        let packet = Packet::parse(&removed_query).unwrap();

        let question_domain = packet.questions.first().unwrap().qname.to_string();
        assert_eq!(
            question_domain,
            "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd"
        );

        let answer1_domain = packet.answers.first().unwrap().name.to_string();
        assert_eq!(
            answer1_domain,
            "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd"
        );
        let answer2_domain = packet.answers.get(1).unwrap().name.to_string();
        assert_eq!(answer2_domain, "example.com");
    }

    #[tokio::test]
    async fn add_success_2_label() {
        let tld = TopLevelDomain("pkd".to_string());
        let domain = create_reply_with_domain("test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy");
        let mut packet = Packet::parse(&domain).unwrap();
        tld.add(&mut packet);
        // Rebuild packet from scratch
        let removed_query = packet.build_bytes_vec().unwrap();
        let packet = Packet::parse(&removed_query).unwrap();

        let question_domain = packet.questions.first().unwrap().qname.to_string();
        assert_eq!(
            question_domain,
            "test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd"
        );

        let answer1_domain = packet.answers.first().unwrap().name.to_string();
        assert_eq!(
            answer1_domain,
            "test.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.pkd"
        );
        let answer2_domain = packet.answers.get(1).unwrap().name.to_string();
        assert_eq!(answer2_domain, "example.com");
    }
}

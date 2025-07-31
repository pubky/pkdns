use pkarr::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum PubkeyParserError {
    #[error("Invalid public key. {0}")]
    InvalidKey(String),
    #[error("Key is valid zbase32 and length but the last bits are incorrect.")]
    ValidButDifferent,
}

/// Parses a public key domain from it's zbase32 format.
pub fn parse_pkarr_uri(uri: &str) -> Result<PublicKey, PubkeyParserError> {
    let decoded = match zbase32::decode_full_bytes_str(uri) {
        Ok(bytes) => bytes,
        Err(e) => return Err(PubkeyParserError::InvalidKey(e.to_string())),
    };
    if decoded.len() != 32 {
        return Err(PubkeyParserError::InvalidKey(
            "zbase32 pubkey should be 32 bytes but is not.".to_string(),
        ));
    };
    let encoded = zbase32::encode_full_bytes(&decoded);
    if encoded.as_str() != uri {
        tracing::trace!(
            "Uri {uri} is not a valid public key. Error corrected should be {encoded}. Failed to parse pkarr pubkey."
        );
        return Err(PubkeyParserError::ValidButDifferent);
    }

    let trying: Result<PublicKey, _> = uri.try_into();
    trying.map_err(|err| PubkeyParserError::InvalidKey(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pkarr_uri() {
        let uri = "7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy";
        let pubkey: PublicKey = uri.try_into().unwrap();
        assert_eq!(pubkey.to_string(), uri);
    }
}

use rand::{thread_rng, Rng};
use rayon::prelude::*;
use regex::Regex;
use starknet::core::types::FieldElement;
use starknet::core::utils::get_contract_address;

// (salt, address)
type VanityAddress = (FieldElement, FieldElement);

/// Find the salt for contract deployment that
/// would result in a contract address that match
/// the given pattern.
///
/// # Arguments
/// * `constructor_calldata` - The inputs for the contract constructor
/// * `deployer` - Address of the contract deployer. Set to `None` if you don't want
/// the contract address to be affected by the deployer's address.
///
/// Generates the contract address until `matcher` matches the address, given the contract deployment data.
pub fn find_vanity_contract_address<T: VanityMatcher>(
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
    deployer: Option<FieldElement>,
    matcher: T,
) -> Option<FieldElement> {
    wallet_generator(class_hash, constructor_calldata, deployer)
        .find_any(create_matcher(matcher))
        .map(|(salt, _)| salt)
}

/// Creates a salt matcher function, which takes a reference to a [FieldElement] and returns
/// whether it found a match or not by using `matcher`.
#[inline]
pub fn create_matcher<T: VanityMatcher>(matcher: T) -> impl Fn(&VanityAddress) -> bool {
    move |(_, addr)| matcher.is_match(addr)
}

/// Returns an infinite parallel iterator which yields a [FieldElement].
#[inline]
pub fn wallet_generator(
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
    deployer: Option<FieldElement>,
) -> impl ParallelIterator<Item = VanityAddress> + '_ {
    std::iter::repeat(()).par_bridge().map(move |_| {
        compute_contract_address_with_random_salt(class_hash, constructor_calldata, deployer)
    })
}

pub fn compute_contract_address_with_random_salt(
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
    deployer: Option<FieldElement>,
) -> VanityAddress {
    let mut r = [0u64; 4];
    thread_rng().fill(&mut r);
    let salt = FieldElement::from_mont(r);

    let addr = get_contract_address(
        salt,
        class_hash,
        constructor_calldata,
        deployer.unwrap_or(FieldElement::ZERO),
    );

    (salt, addr)
}

/// A trait to match vanity addresses.
pub trait VanityMatcher: Send + Sync {
    fn is_match(&self, addr: &FieldElement) -> bool;
}

/// Matches start and end hex.
pub struct HexMatcher {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}

impl VanityMatcher for HexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let bytes = addr.to_bytes_be();
        bytes.starts_with(&self.left) && bytes.ends_with(&self.right)
    }
}

/// Matches only start hex.
pub struct LeftHexMatcher {
    pub left: Vec<u8>,
}

impl VanityMatcher for LeftHexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let bytes = addr.to_bytes_be();
        bytes.starts_with(&self.left)
    }
}

/// Matches only end hex.
pub struct RightHexMatcher {
    pub right: Vec<u8>,
}

impl VanityMatcher for RightHexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let bytes = addr.to_bytes_be();
        bytes.ends_with(&self.right)
    }
}

/// Matches start hex and end regex.
pub struct LeftExactRightRegexMatcher {
    pub left: Vec<u8>,
    pub right: Regex,
}

impl VanityMatcher for LeftExactRightRegexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let bytes = addr.to_bytes_be();
        bytes.starts_with(&self.left) && self.right.is_match(&hex::encode(bytes))
    }
}

/// Matches start regex and end hex.
pub struct LeftRegexRightExactMatcher {
    pub left: Regex,
    pub right: Vec<u8>,
}

impl VanityMatcher for LeftRegexRightExactMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let bytes = addr.to_bytes_be();
        bytes.ends_with(&self.right) && self.left.is_match(&hex::encode(bytes))
    }
}

/// Matches a single regex.
pub struct SingleRegexMatcher {
    pub re: Regex,
}

impl VanityMatcher for SingleRegexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let addr = format!("{addr:x}");
        self.re.is_match(&addr)
    }
}

/// Matches start and end regex.
pub struct RegexMatcher {
    pub left: Regex,
    pub right: Regex,
}

impl VanityMatcher for RegexMatcher {
    #[inline]
    fn is_match(&self, addr: &FieldElement) -> bool {
        let addr = format!("{addr:x}");
        self.left.is_match(&addr) && self.right.is_match(&addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministically_find_vanity_address_with_regex_prefix() {
        let regex = Regex::new(&format!(r"^6969")).unwrap();
        let matcher = SingleRegexMatcher { re: regex.clone() };

        let contract_data = (
            FieldElement::from_hex_be("0x123456").unwrap(),
            &[
                FieldElement::from_hex_be("0x4290").unwrap(),
                FieldElement::from_hex_be("0x7777").unwrap(),
            ],
        );

        let salt =
            find_vanity_contract_address(contract_data.0, contract_data.1, None, matcher).unwrap();
        let address =
            get_contract_address(salt, contract_data.0, contract_data.1, FieldElement::ZERO);

        assert!(regex.is_match(&format!("{:x}", address)))
    }

    #[test]
    fn deterministically_find_vanity_address_with_regex_suffix() {
        let regex = Regex::new(&format!(r"2077$")).unwrap();
        let matcher = SingleRegexMatcher { re: regex.clone() };

        let contract_data = (
            FieldElement::from_hex_be("0x123456").unwrap(),
            &[
                FieldElement::from_hex_be("0x4290").unwrap(),
                FieldElement::from_hex_be("0x7777").unwrap(),
            ],
        );

        let salt =
            find_vanity_contract_address(contract_data.0, contract_data.1, None, matcher).unwrap();
        let address =
            get_contract_address(salt, contract_data.0, contract_data.1, FieldElement::ZERO);

        assert!(regex.is_match(&format!("{:x}", address)))
    }

    #[test]
    fn deterministically_find_vanity_address_with_hex_prefix() {
        let prefix = hex::decode("0000".as_bytes()).unwrap();
        let matcher = LeftHexMatcher {
            left: prefix.clone(),
        };

        let contract_data = (
            FieldElement::from_hex_be("0x123456").unwrap(),
            &[
                FieldElement::from_hex_be("0x4290").unwrap(),
                FieldElement::from_hex_be("0x7777").unwrap(),
            ],
        );

        let salt =
            find_vanity_contract_address(contract_data.0, contract_data.1, None, matcher).unwrap();
        let address =
            get_contract_address(salt, contract_data.0, contract_data.1, FieldElement::ZERO);

        assert!(address.to_bytes_be().starts_with(&prefix));
    }

    #[test]
    fn deterministically_find_vanity_address_with_hex_suffix() {
        let prefix = hex::decode("33".as_bytes()).unwrap();
        let matcher = RightHexMatcher {
            right: prefix.clone(),
        };

        let contract_data = (
            FieldElement::from_hex_be("0x123456").unwrap(),
            &[
                FieldElement::from_hex_be("0x4290").unwrap(),
                FieldElement::from_hex_be("0x7777").unwrap(),
            ],
        );

        let salt =
            find_vanity_contract_address(contract_data.0, contract_data.1, None, matcher).unwrap();
        let address =
            get_contract_address(salt, contract_data.0, contract_data.1, FieldElement::ZERO);

        assert!(address.to_bytes_be().ends_with(&prefix));
    }
}

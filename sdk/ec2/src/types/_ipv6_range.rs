// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an IPv6 address range.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ipv6Range {
    /// <p>A description for the security group rule that references this IPv6 address range.</p>
    /// <p>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@\[\]+=&amp;;{}!$*</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The IPv6 address range. You can either specify a CIDR block or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</p><note>
    /// <p>Amazon Web Services <a href="https://en.wikipedia.org/wiki/Canonicalization">canonicalizes</a> IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR block, Amazon Web Services canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups and DescribeSecurityGroupRules calls will return the canonicalized form of the CIDR block. Additionally, if you attempt to add another rule with the non-canonical form of the CIDR (such as 100.68.0.18/18) and there is already a rule for the canonicalized form of the CIDR block (such as 100.68.0.0/18), the API throws an duplicate rule error.</p>
    /// </note>
    pub cidr_ipv6: ::std::option::Option<::std::string::String>,
}
impl Ipv6Range {
    /// <p>A description for the security group rule that references this IPv6 address range.</p>
    /// <p>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@\[\]+=&amp;;{}!$*</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The IPv6 address range. You can either specify a CIDR block or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</p><note>
    /// <p>Amazon Web Services <a href="https://en.wikipedia.org/wiki/Canonicalization">canonicalizes</a> IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR block, Amazon Web Services canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups and DescribeSecurityGroupRules calls will return the canonicalized form of the CIDR block. Additionally, if you attempt to add another rule with the non-canonical form of the CIDR (such as 100.68.0.18/18) and there is already a rule for the canonicalized form of the CIDR block (such as 100.68.0.0/18), the API throws an duplicate rule error.</p>
    /// </note>
    pub fn cidr_ipv6(&self) -> ::std::option::Option<&str> {
        self.cidr_ipv6.as_deref()
    }
}
impl Ipv6Range {
    /// Creates a new builder-style object to manufacture [`Ipv6Range`](crate::types::Ipv6Range).
    pub fn builder() -> crate::types::builders::Ipv6RangeBuilder {
        crate::types::builders::Ipv6RangeBuilder::default()
    }
}

/// A builder for [`Ipv6Range`](crate::types::Ipv6Range).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ipv6RangeBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) cidr_ipv6: ::std::option::Option<::std::string::String>,
}
impl Ipv6RangeBuilder {
    /// <p>A description for the security group rule that references this IPv6 address range.</p>
    /// <p>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@\[\]+=&amp;;{}!$*</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the security group rule that references this IPv6 address range.</p>
    /// <p>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@\[\]+=&amp;;{}!$*</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the security group rule that references this IPv6 address range.</p>
    /// <p>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@\[\]+=&amp;;{}!$*</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The IPv6 address range. You can either specify a CIDR block or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</p><note>
    /// <p>Amazon Web Services <a href="https://en.wikipedia.org/wiki/Canonicalization">canonicalizes</a> IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR block, Amazon Web Services canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups and DescribeSecurityGroupRules calls will return the canonicalized form of the CIDR block. Additionally, if you attempt to add another rule with the non-canonical form of the CIDR (such as 100.68.0.18/18) and there is already a rule for the canonicalized form of the CIDR block (such as 100.68.0.0/18), the API throws an duplicate rule error.</p>
    /// </note>
    pub fn cidr_ipv6(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr_ipv6 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv6 address range. You can either specify a CIDR block or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</p><note>
    /// <p>Amazon Web Services <a href="https://en.wikipedia.org/wiki/Canonicalization">canonicalizes</a> IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR block, Amazon Web Services canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups and DescribeSecurityGroupRules calls will return the canonicalized form of the CIDR block. Additionally, if you attempt to add another rule with the non-canonical form of the CIDR (such as 100.68.0.18/18) and there is already a rule for the canonicalized form of the CIDR block (such as 100.68.0.0/18), the API throws an duplicate rule error.</p>
    /// </note>
    pub fn set_cidr_ipv6(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr_ipv6 = input;
        self
    }
    /// <p>The IPv6 address range. You can either specify a CIDR block or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</p><note>
    /// <p>Amazon Web Services <a href="https://en.wikipedia.org/wiki/Canonicalization">canonicalizes</a> IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR block, Amazon Web Services canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups and DescribeSecurityGroupRules calls will return the canonicalized form of the CIDR block. Additionally, if you attempt to add another rule with the non-canonical form of the CIDR (such as 100.68.0.18/18) and there is already a rule for the canonicalized form of the CIDR block (such as 100.68.0.0/18), the API throws an duplicate rule error.</p>
    /// </note>
    pub fn get_cidr_ipv6(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr_ipv6
    }
    /// Consumes the builder and constructs a [`Ipv6Range`](crate::types::Ipv6Range).
    pub fn build(self) -> crate::types::Ipv6Range {
        crate::types::Ipv6Range {
            description: self.description,
            cidr_ipv6: self.cidr_ipv6,
        }
    }
}

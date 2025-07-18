// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>To use simple format for S3 keys for log objects, set SimplePrefix to an empty object.</p>
/// <p><code>\[DestinationPrefix\]\[YYYY\]-\[MM\]-\[DD\]-\[hh\]-\[mm\]-\[ss\]-\[UniqueString\]</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SimplePrefix {}
impl SimplePrefix {
    /// Creates a new builder-style object to manufacture [`SimplePrefix`](crate::types::SimplePrefix).
    pub fn builder() -> crate::types::builders::SimplePrefixBuilder {
        crate::types::builders::SimplePrefixBuilder::default()
    }
}

/// A builder for [`SimplePrefix`](crate::types::SimplePrefix).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SimplePrefixBuilder {}
impl SimplePrefixBuilder {
    /// Consumes the builder and constructs a [`SimplePrefix`](crate::types::SimplePrefix).
    pub fn build(self) -> crate::types::SimplePrefix {
        crate::types::SimplePrefix {}
    }
}

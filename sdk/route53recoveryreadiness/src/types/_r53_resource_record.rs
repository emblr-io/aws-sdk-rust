// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Route 53 resource that a DNS target resource record points to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct R53ResourceRecord {
    /// <p>The DNS target domain name.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The Route 53 Resource Record Set ID.</p>
    pub record_set_id: ::std::option::Option<::std::string::String>,
}
impl R53ResourceRecord {
    /// <p>The DNS target domain name.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The Route 53 Resource Record Set ID.</p>
    pub fn record_set_id(&self) -> ::std::option::Option<&str> {
        self.record_set_id.as_deref()
    }
}
impl R53ResourceRecord {
    /// Creates a new builder-style object to manufacture [`R53ResourceRecord`](crate::types::R53ResourceRecord).
    pub fn builder() -> crate::types::builders::R53ResourceRecordBuilder {
        crate::types::builders::R53ResourceRecordBuilder::default()
    }
}

/// A builder for [`R53ResourceRecord`](crate::types::R53ResourceRecord).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct R53ResourceRecordBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) record_set_id: ::std::option::Option<::std::string::String>,
}
impl R53ResourceRecordBuilder {
    /// <p>The DNS target domain name.</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DNS target domain name.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The DNS target domain name.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The Route 53 Resource Record Set ID.</p>
    pub fn record_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.record_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Route 53 Resource Record Set ID.</p>
    pub fn set_record_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.record_set_id = input;
        self
    }
    /// <p>The Route 53 Resource Record Set ID.</p>
    pub fn get_record_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.record_set_id
    }
    /// Consumes the builder and constructs a [`R53ResourceRecord`](crate::types::R53ResourceRecord).
    pub fn build(self) -> crate::types::R53ResourceRecord {
        crate::types::R53ResourceRecord {
            domain_name: self.domain_name,
            record_set_id: self.record_set_id,
        }
    }
}

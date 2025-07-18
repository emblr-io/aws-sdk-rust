// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a prefix list entry.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrefixListEntry {
    /// <p>The CIDR block.</p>
    pub cidr: ::std::option::Option<::std::string::String>,
    /// <p>The description.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl PrefixListEntry {
    /// <p>The CIDR block.</p>
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
    /// <p>The description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl PrefixListEntry {
    /// Creates a new builder-style object to manufacture [`PrefixListEntry`](crate::types::PrefixListEntry).
    pub fn builder() -> crate::types::builders::PrefixListEntryBuilder {
        crate::types::builders::PrefixListEntryBuilder::default()
    }
}

/// A builder for [`PrefixListEntry`](crate::types::PrefixListEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrefixListEntryBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl PrefixListEntryBuilder {
    /// <p>The CIDR block.</p>
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CIDR block.</p>
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// <p>The CIDR block.</p>
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// <p>The description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`PrefixListEntry`](crate::types::PrefixListEntry).
    pub fn build(self) -> crate::types::PrefixListEntry {
        crate::types::PrefixListEntry {
            cidr: self.cidr,
            description: self.description,
        }
    }
}

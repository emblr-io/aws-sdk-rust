// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the configuration information required to join fleets and image builders to Microsoft Active Directory domains.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainJoinInfo {
    /// <p>The fully qualified name of the directory (for example, corp.example.com).</p>
    pub directory_name: ::std::option::Option<::std::string::String>,
    /// <p>The distinguished name of the organizational unit for computer accounts.</p>
    pub organizational_unit_distinguished_name: ::std::option::Option<::std::string::String>,
}
impl DomainJoinInfo {
    /// <p>The fully qualified name of the directory (for example, corp.example.com).</p>
    pub fn directory_name(&self) -> ::std::option::Option<&str> {
        self.directory_name.as_deref()
    }
    /// <p>The distinguished name of the organizational unit for computer accounts.</p>
    pub fn organizational_unit_distinguished_name(&self) -> ::std::option::Option<&str> {
        self.organizational_unit_distinguished_name.as_deref()
    }
}
impl DomainJoinInfo {
    /// Creates a new builder-style object to manufacture [`DomainJoinInfo`](crate::types::DomainJoinInfo).
    pub fn builder() -> crate::types::builders::DomainJoinInfoBuilder {
        crate::types::builders::DomainJoinInfoBuilder::default()
    }
}

/// A builder for [`DomainJoinInfo`](crate::types::DomainJoinInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainJoinInfoBuilder {
    pub(crate) directory_name: ::std::option::Option<::std::string::String>,
    pub(crate) organizational_unit_distinguished_name: ::std::option::Option<::std::string::String>,
}
impl DomainJoinInfoBuilder {
    /// <p>The fully qualified name of the directory (for example, corp.example.com).</p>
    pub fn directory_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified name of the directory (for example, corp.example.com).</p>
    pub fn set_directory_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_name = input;
        self
    }
    /// <p>The fully qualified name of the directory (for example, corp.example.com).</p>
    pub fn get_directory_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_name
    }
    /// <p>The distinguished name of the organizational unit for computer accounts.</p>
    pub fn organizational_unit_distinguished_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organizational_unit_distinguished_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The distinguished name of the organizational unit for computer accounts.</p>
    pub fn set_organizational_unit_distinguished_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organizational_unit_distinguished_name = input;
        self
    }
    /// <p>The distinguished name of the organizational unit for computer accounts.</p>
    pub fn get_organizational_unit_distinguished_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.organizational_unit_distinguished_name
    }
    /// Consumes the builder and constructs a [`DomainJoinInfo`](crate::types::DomainJoinInfo).
    pub fn build(self) -> crate::types::DomainJoinInfo {
        crate::types::DomainJoinInfo {
            directory_name: self.directory_name,
            organizational_unit_distinguished_name: self.organizational_unit_distinguished_name,
        }
    }
}

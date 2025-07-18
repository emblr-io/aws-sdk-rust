// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>DeleteIndexField</code></code> operation. Specifies the name of the domain you want to update and the name of the index field you want to delete.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIndexFieldInput {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the index field your want to remove from the domain's indexing options.</p>
    pub index_field_name: ::std::option::Option<::std::string::String>,
}
impl DeleteIndexFieldInput {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The name of the index field your want to remove from the domain's indexing options.</p>
    pub fn index_field_name(&self) -> ::std::option::Option<&str> {
        self.index_field_name.as_deref()
    }
}
impl DeleteIndexFieldInput {
    /// Creates a new builder-style object to manufacture [`DeleteIndexFieldInput`](crate::operation::delete_index_field::DeleteIndexFieldInput).
    pub fn builder() -> crate::operation::delete_index_field::builders::DeleteIndexFieldInputBuilder {
        crate::operation::delete_index_field::builders::DeleteIndexFieldInputBuilder::default()
    }
}

/// A builder for [`DeleteIndexFieldInput`](crate::operation::delete_index_field::DeleteIndexFieldInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIndexFieldInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) index_field_name: ::std::option::Option<::std::string::String>,
}
impl DeleteIndexFieldInputBuilder {
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>A string that represents the name of a domain. Domain names are unique across the domains owned by an account within an AWS region. Domain names start with a letter or number and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The name of the index field your want to remove from the domain's indexing options.</p>
    /// This field is required.
    pub fn index_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the index field your want to remove from the domain's indexing options.</p>
    pub fn set_index_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_field_name = input;
        self
    }
    /// <p>The name of the index field your want to remove from the domain's indexing options.</p>
    pub fn get_index_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_field_name
    }
    /// Consumes the builder and constructs a [`DeleteIndexFieldInput`](crate::operation::delete_index_field::DeleteIndexFieldInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_index_field::DeleteIndexFieldInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_index_field::DeleteIndexFieldInput {
            domain_name: self.domain_name,
            index_field_name: self.index_field_name,
        })
    }
}

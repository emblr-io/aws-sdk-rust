// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGlossaryInput {
    /// <p>The ID of the Amazon DataZone domain in which the business glossary is deleted.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the business glossary that is deleted.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteGlossaryInput {
    /// <p>The ID of the Amazon DataZone domain in which the business glossary is deleted.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The ID of the business glossary that is deleted.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl DeleteGlossaryInput {
    /// Creates a new builder-style object to manufacture [`DeleteGlossaryInput`](crate::operation::delete_glossary::DeleteGlossaryInput).
    pub fn builder() -> crate::operation::delete_glossary::builders::DeleteGlossaryInputBuilder {
        crate::operation::delete_glossary::builders::DeleteGlossaryInputBuilder::default()
    }
}

/// A builder for [`DeleteGlossaryInput`](crate::operation::delete_glossary::DeleteGlossaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGlossaryInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteGlossaryInputBuilder {
    /// <p>The ID of the Amazon DataZone domain in which the business glossary is deleted.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the business glossary is deleted.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the business glossary is deleted.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The ID of the business glossary that is deleted.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the business glossary that is deleted.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The ID of the business glossary that is deleted.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`DeleteGlossaryInput`](crate::operation::delete_glossary::DeleteGlossaryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_glossary::DeleteGlossaryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_glossary::DeleteGlossaryInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
        })
    }
}

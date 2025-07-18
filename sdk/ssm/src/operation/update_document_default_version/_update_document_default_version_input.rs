// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDocumentDefaultVersionInput {
    /// <p>The name of a custom document that you want to set as the default version.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of a custom document that you want to set as the default version.</p>
    pub document_version: ::std::option::Option<::std::string::String>,
}
impl UpdateDocumentDefaultVersionInput {
    /// <p>The name of a custom document that you want to set as the default version.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of a custom document that you want to set as the default version.</p>
    pub fn document_version(&self) -> ::std::option::Option<&str> {
        self.document_version.as_deref()
    }
}
impl UpdateDocumentDefaultVersionInput {
    /// Creates a new builder-style object to manufacture [`UpdateDocumentDefaultVersionInput`](crate::operation::update_document_default_version::UpdateDocumentDefaultVersionInput).
    pub fn builder() -> crate::operation::update_document_default_version::builders::UpdateDocumentDefaultVersionInputBuilder {
        crate::operation::update_document_default_version::builders::UpdateDocumentDefaultVersionInputBuilder::default()
    }
}

/// A builder for [`UpdateDocumentDefaultVersionInput`](crate::operation::update_document_default_version::UpdateDocumentDefaultVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDocumentDefaultVersionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) document_version: ::std::option::Option<::std::string::String>,
}
impl UpdateDocumentDefaultVersionInputBuilder {
    /// <p>The name of a custom document that you want to set as the default version.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a custom document that you want to set as the default version.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a custom document that you want to set as the default version.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of a custom document that you want to set as the default version.</p>
    /// This field is required.
    pub fn document_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of a custom document that you want to set as the default version.</p>
    pub fn set_document_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_version = input;
        self
    }
    /// <p>The version of a custom document that you want to set as the default version.</p>
    pub fn get_document_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_version
    }
    /// Consumes the builder and constructs a [`UpdateDocumentDefaultVersionInput`](crate::operation::update_document_default_version::UpdateDocumentDefaultVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_document_default_version::UpdateDocumentDefaultVersionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_document_default_version::UpdateDocumentDefaultVersionInput {
            name: self.name,
            document_version: self.document_version,
        })
    }
}

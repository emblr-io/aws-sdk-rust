// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAssetInput {
    /// <p>The ID of the Amazon DataZone domain in which the asset is deleted.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the asset that is deleted.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteAssetInput {
    /// <p>The ID of the Amazon DataZone domain in which the asset is deleted.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the asset that is deleted.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl DeleteAssetInput {
    /// Creates a new builder-style object to manufacture [`DeleteAssetInput`](crate::operation::delete_asset::DeleteAssetInput).
    pub fn builder() -> crate::operation::delete_asset::builders::DeleteAssetInputBuilder {
        crate::operation::delete_asset::builders::DeleteAssetInputBuilder::default()
    }
}

/// A builder for [`DeleteAssetInput`](crate::operation::delete_asset::DeleteAssetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAssetInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteAssetInputBuilder {
    /// <p>The ID of the Amazon DataZone domain in which the asset is deleted.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the asset is deleted.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the asset is deleted.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the asset that is deleted.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the asset that is deleted.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the asset that is deleted.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`DeleteAssetInput`](crate::operation::delete_asset::DeleteAssetInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_asset::DeleteAssetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_asset::DeleteAssetInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
        })
    }
}

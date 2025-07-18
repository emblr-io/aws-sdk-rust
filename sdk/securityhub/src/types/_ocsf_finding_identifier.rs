// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides a standard to identify security findings using OCSF.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OcsfFindingIdentifier {
    /// <p>Finding cloud.account.uid, which is a unique identifier in the Amazon Web Services account..</p>
    pub cloud_account_uid: ::std::option::Option<::std::string::String>,
    /// <p>Finding finding_info.uid, which is a unique identifier for the finding from the finding provider.</p>
    pub finding_info_uid: ::std::option::Option<::std::string::String>,
    /// <p>Finding metadata.product.uid, which is a unique identifier for the product.</p>
    pub metadata_product_uid: ::std::option::Option<::std::string::String>,
}
impl OcsfFindingIdentifier {
    /// <p>Finding cloud.account.uid, which is a unique identifier in the Amazon Web Services account..</p>
    pub fn cloud_account_uid(&self) -> ::std::option::Option<&str> {
        self.cloud_account_uid.as_deref()
    }
    /// <p>Finding finding_info.uid, which is a unique identifier for the finding from the finding provider.</p>
    pub fn finding_info_uid(&self) -> ::std::option::Option<&str> {
        self.finding_info_uid.as_deref()
    }
    /// <p>Finding metadata.product.uid, which is a unique identifier for the product.</p>
    pub fn metadata_product_uid(&self) -> ::std::option::Option<&str> {
        self.metadata_product_uid.as_deref()
    }
}
impl OcsfFindingIdentifier {
    /// Creates a new builder-style object to manufacture [`OcsfFindingIdentifier`](crate::types::OcsfFindingIdentifier).
    pub fn builder() -> crate::types::builders::OcsfFindingIdentifierBuilder {
        crate::types::builders::OcsfFindingIdentifierBuilder::default()
    }
}

/// A builder for [`OcsfFindingIdentifier`](crate::types::OcsfFindingIdentifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OcsfFindingIdentifierBuilder {
    pub(crate) cloud_account_uid: ::std::option::Option<::std::string::String>,
    pub(crate) finding_info_uid: ::std::option::Option<::std::string::String>,
    pub(crate) metadata_product_uid: ::std::option::Option<::std::string::String>,
}
impl OcsfFindingIdentifierBuilder {
    /// <p>Finding cloud.account.uid, which is a unique identifier in the Amazon Web Services account..</p>
    /// This field is required.
    pub fn cloud_account_uid(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_account_uid = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Finding cloud.account.uid, which is a unique identifier in the Amazon Web Services account..</p>
    pub fn set_cloud_account_uid(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_account_uid = input;
        self
    }
    /// <p>Finding cloud.account.uid, which is a unique identifier in the Amazon Web Services account..</p>
    pub fn get_cloud_account_uid(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_account_uid
    }
    /// <p>Finding finding_info.uid, which is a unique identifier for the finding from the finding provider.</p>
    /// This field is required.
    pub fn finding_info_uid(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.finding_info_uid = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Finding finding_info.uid, which is a unique identifier for the finding from the finding provider.</p>
    pub fn set_finding_info_uid(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.finding_info_uid = input;
        self
    }
    /// <p>Finding finding_info.uid, which is a unique identifier for the finding from the finding provider.</p>
    pub fn get_finding_info_uid(&self) -> &::std::option::Option<::std::string::String> {
        &self.finding_info_uid
    }
    /// <p>Finding metadata.product.uid, which is a unique identifier for the product.</p>
    /// This field is required.
    pub fn metadata_product_uid(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metadata_product_uid = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Finding metadata.product.uid, which is a unique identifier for the product.</p>
    pub fn set_metadata_product_uid(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metadata_product_uid = input;
        self
    }
    /// <p>Finding metadata.product.uid, which is a unique identifier for the product.</p>
    pub fn get_metadata_product_uid(&self) -> &::std::option::Option<::std::string::String> {
        &self.metadata_product_uid
    }
    /// Consumes the builder and constructs a [`OcsfFindingIdentifier`](crate::types::OcsfFindingIdentifier).
    pub fn build(self) -> crate::types::OcsfFindingIdentifier {
        crate::types::OcsfFindingIdentifier {
            cloud_account_uid: self.cloud_account_uid,
            finding_info_uid: self.finding_info_uid,
            metadata_product_uid: self.metadata_product_uid,
        }
    }
}

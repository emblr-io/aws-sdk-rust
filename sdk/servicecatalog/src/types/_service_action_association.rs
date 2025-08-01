// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A self-service action association consisting of the Action ID, the Product ID, and the Provisioning Artifact ID.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceActionAssociation {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub service_action_id: ::std::string::String,
    /// <p>The product identifier. For example, <code>prod-abcdzk7xy33qa</code>.</p>
    pub product_id: ::std::string::String,
    /// <p>The identifier of the provisioning artifact. For example, <code>pa-4abcdjnxjj6ne</code>.</p>
    pub provisioning_artifact_id: ::std::string::String,
}
impl ServiceActionAssociation {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn service_action_id(&self) -> &str {
        use std::ops::Deref;
        self.service_action_id.deref()
    }
    /// <p>The product identifier. For example, <code>prod-abcdzk7xy33qa</code>.</p>
    pub fn product_id(&self) -> &str {
        use std::ops::Deref;
        self.product_id.deref()
    }
    /// <p>The identifier of the provisioning artifact. For example, <code>pa-4abcdjnxjj6ne</code>.</p>
    pub fn provisioning_artifact_id(&self) -> &str {
        use std::ops::Deref;
        self.provisioning_artifact_id.deref()
    }
}
impl ServiceActionAssociation {
    /// Creates a new builder-style object to manufacture [`ServiceActionAssociation`](crate::types::ServiceActionAssociation).
    pub fn builder() -> crate::types::builders::ServiceActionAssociationBuilder {
        crate::types::builders::ServiceActionAssociationBuilder::default()
    }
}

/// A builder for [`ServiceActionAssociation`](crate::types::ServiceActionAssociation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceActionAssociationBuilder {
    pub(crate) service_action_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_id: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_artifact_id: ::std::option::Option<::std::string::String>,
}
impl ServiceActionAssociationBuilder {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    /// This field is required.
    pub fn service_action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn set_service_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_action_id = input;
        self
    }
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn get_service_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_action_id
    }
    /// <p>The product identifier. For example, <code>prod-abcdzk7xy33qa</code>.</p>
    /// This field is required.
    pub fn product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The product identifier. For example, <code>prod-abcdzk7xy33qa</code>.</p>
    pub fn set_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_id = input;
        self
    }
    /// <p>The product identifier. For example, <code>prod-abcdzk7xy33qa</code>.</p>
    pub fn get_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_id
    }
    /// <p>The identifier of the provisioning artifact. For example, <code>pa-4abcdjnxjj6ne</code>.</p>
    /// This field is required.
    pub fn provisioning_artifact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioning_artifact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioning artifact. For example, <code>pa-4abcdjnxjj6ne</code>.</p>
    pub fn set_provisioning_artifact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioning_artifact_id = input;
        self
    }
    /// <p>The identifier of the provisioning artifact. For example, <code>pa-4abcdjnxjj6ne</code>.</p>
    pub fn get_provisioning_artifact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioning_artifact_id
    }
    /// Consumes the builder and constructs a [`ServiceActionAssociation`](crate::types::ServiceActionAssociation).
    /// This method will fail if any of the following fields are not set:
    /// - [`service_action_id`](crate::types::builders::ServiceActionAssociationBuilder::service_action_id)
    /// - [`product_id`](crate::types::builders::ServiceActionAssociationBuilder::product_id)
    /// - [`provisioning_artifact_id`](crate::types::builders::ServiceActionAssociationBuilder::provisioning_artifact_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ServiceActionAssociation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ServiceActionAssociation {
            service_action_id: self.service_action_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_action_id",
                    "service_action_id was not specified but it is required when building ServiceActionAssociation",
                )
            })?,
            product_id: self.product_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "product_id",
                    "product_id was not specified but it is required when building ServiceActionAssociation",
                )
            })?,
            provisioning_artifact_id: self.provisioning_artifact_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "provisioning_artifact_id",
                    "provisioning_artifact_id was not specified but it is required when building ServiceActionAssociation",
                )
            })?,
        })
    }
}

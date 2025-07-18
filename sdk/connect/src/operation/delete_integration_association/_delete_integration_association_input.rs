// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIntegrationAssociationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the integration association.</p>
    pub integration_association_id: ::std::option::Option<::std::string::String>,
}
impl DeleteIntegrationAssociationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier for the integration association.</p>
    pub fn integration_association_id(&self) -> ::std::option::Option<&str> {
        self.integration_association_id.as_deref()
    }
}
impl DeleteIntegrationAssociationInput {
    /// Creates a new builder-style object to manufacture [`DeleteIntegrationAssociationInput`](crate::operation::delete_integration_association::DeleteIntegrationAssociationInput).
    pub fn builder() -> crate::operation::delete_integration_association::builders::DeleteIntegrationAssociationInputBuilder {
        crate::operation::delete_integration_association::builders::DeleteIntegrationAssociationInputBuilder::default()
    }
}

/// A builder for [`DeleteIntegrationAssociationInput`](crate::operation::delete_integration_association::DeleteIntegrationAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIntegrationAssociationInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) integration_association_id: ::std::option::Option<::std::string::String>,
}
impl DeleteIntegrationAssociationInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier for the integration association.</p>
    /// This field is required.
    pub fn integration_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the integration association.</p>
    pub fn set_integration_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_association_id = input;
        self
    }
    /// <p>The identifier for the integration association.</p>
    pub fn get_integration_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_association_id
    }
    /// Consumes the builder and constructs a [`DeleteIntegrationAssociationInput`](crate::operation::delete_integration_association::DeleteIntegrationAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_integration_association::DeleteIntegrationAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_integration_association::DeleteIntegrationAssociationInput {
            instance_id: self.instance_id,
            integration_association_id: self.integration_association_id,
        })
    }
}

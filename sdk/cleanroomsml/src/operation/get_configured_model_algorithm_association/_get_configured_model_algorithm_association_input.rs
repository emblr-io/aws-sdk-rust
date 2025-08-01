// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfiguredModelAlgorithmAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    /// <p>The membership ID of the member that created the configured model algorithm association.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
}
impl GetConfiguredModelAlgorithmAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub fn configured_model_algorithm_association_arn(&self) -> ::std::option::Option<&str> {
        self.configured_model_algorithm_association_arn.as_deref()
    }
    /// <p>The membership ID of the member that created the configured model algorithm association.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
}
impl GetConfiguredModelAlgorithmAssociationInput {
    /// Creates a new builder-style object to manufacture [`GetConfiguredModelAlgorithmAssociationInput`](crate::operation::get_configured_model_algorithm_association::GetConfiguredModelAlgorithmAssociationInput).
    pub fn builder() -> crate::operation::get_configured_model_algorithm_association::builders::GetConfiguredModelAlgorithmAssociationInputBuilder {
        crate::operation::get_configured_model_algorithm_association::builders::GetConfiguredModelAlgorithmAssociationInputBuilder::default()
    }
}

/// A builder for [`GetConfiguredModelAlgorithmAssociationInput`](crate::operation::get_configured_model_algorithm_association::GetConfiguredModelAlgorithmAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfiguredModelAlgorithmAssociationInputBuilder {
    pub(crate) configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
}
impl GetConfiguredModelAlgorithmAssociationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    /// This field is required.
    pub fn configured_model_algorithm_association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_model_algorithm_association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub fn set_configured_model_algorithm_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_model_algorithm_association_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub fn get_configured_model_algorithm_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_model_algorithm_association_arn
    }
    /// <p>The membership ID of the member that created the configured model algorithm association.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The membership ID of the member that created the configured model algorithm association.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>The membership ID of the member that created the configured model algorithm association.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// Consumes the builder and constructs a [`GetConfiguredModelAlgorithmAssociationInput`](crate::operation::get_configured_model_algorithm_association::GetConfiguredModelAlgorithmAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_configured_model_algorithm_association::GetConfiguredModelAlgorithmAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_configured_model_algorithm_association::GetConfiguredModelAlgorithmAssociationInput {
                configured_model_algorithm_association_arn: self.configured_model_algorithm_association_arn,
                membership_identifier: self.membership_identifier,
            },
        )
    }
}

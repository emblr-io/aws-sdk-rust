// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCollaborationConfiguredModelAlgorithmAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    /// <p>The collaboration ID for the collaboration that contains the configured model algorithm association that you want to return information about.</p>
    pub collaboration_identifier: ::std::option::Option<::std::string::String>,
}
impl GetCollaborationConfiguredModelAlgorithmAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the configured model algorithm association that you want to return information about.</p>
    pub fn configured_model_algorithm_association_arn(&self) -> ::std::option::Option<&str> {
        self.configured_model_algorithm_association_arn.as_deref()
    }
    /// <p>The collaboration ID for the collaboration that contains the configured model algorithm association that you want to return information about.</p>
    pub fn collaboration_identifier(&self) -> ::std::option::Option<&str> {
        self.collaboration_identifier.as_deref()
    }
}
impl GetCollaborationConfiguredModelAlgorithmAssociationInput {
    /// Creates a new builder-style object to manufacture [`GetCollaborationConfiguredModelAlgorithmAssociationInput`](crate::operation::get_collaboration_configured_model_algorithm_association::GetCollaborationConfiguredModelAlgorithmAssociationInput).
    pub fn builder() -> crate::operation::get_collaboration_configured_model_algorithm_association::builders::GetCollaborationConfiguredModelAlgorithmAssociationInputBuilder{
        crate::operation::get_collaboration_configured_model_algorithm_association::builders::GetCollaborationConfiguredModelAlgorithmAssociationInputBuilder::default()
    }
}

/// A builder for [`GetCollaborationConfiguredModelAlgorithmAssociationInput`](crate::operation::get_collaboration_configured_model_algorithm_association::GetCollaborationConfiguredModelAlgorithmAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCollaborationConfiguredModelAlgorithmAssociationInputBuilder {
    pub(crate) configured_model_algorithm_association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) collaboration_identifier: ::std::option::Option<::std::string::String>,
}
impl GetCollaborationConfiguredModelAlgorithmAssociationInputBuilder {
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
    /// <p>The collaboration ID for the collaboration that contains the configured model algorithm association that you want to return information about.</p>
    /// This field is required.
    pub fn collaboration_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collaboration_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The collaboration ID for the collaboration that contains the configured model algorithm association that you want to return information about.</p>
    pub fn set_collaboration_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collaboration_identifier = input;
        self
    }
    /// <p>The collaboration ID for the collaboration that contains the configured model algorithm association that you want to return information about.</p>
    pub fn get_collaboration_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.collaboration_identifier
    }
    /// Consumes the builder and constructs a [`GetCollaborationConfiguredModelAlgorithmAssociationInput`](crate::operation::get_collaboration_configured_model_algorithm_association::GetCollaborationConfiguredModelAlgorithmAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_collaboration_configured_model_algorithm_association::GetCollaborationConfiguredModelAlgorithmAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_collaboration_configured_model_algorithm_association::GetCollaborationConfiguredModelAlgorithmAssociationInput {
                configured_model_algorithm_association_arn: self.configured_model_algorithm_association_arn,
                collaboration_identifier: self.collaboration_identifier,
            },
        )
    }
}

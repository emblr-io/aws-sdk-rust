// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The metadata that's associated with the delegation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DelegationMetadata {
    /// <p>The unique identifier for the delegation.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the associated assessment.</p>
    pub assessment_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the assessment.</p>
    pub assessment_id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the delegation.</p>
    pub status: ::std::option::Option<crate::types::DelegationStatus>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies when the delegation was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies the name of the control set that was delegated for review.</p>
    pub control_set_name: ::std::option::Option<::std::string::String>,
}
impl DelegationMetadata {
    /// <p>The unique identifier for the delegation.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the associated assessment.</p>
    pub fn assessment_name(&self) -> ::std::option::Option<&str> {
        self.assessment_name.as_deref()
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn assessment_id(&self) -> ::std::option::Option<&str> {
        self.assessment_id.as_deref()
    }
    /// <p>The current status of the delegation.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DelegationStatus> {
        self.status.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Specifies when the delegation was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>Specifies the name of the control set that was delegated for review.</p>
    pub fn control_set_name(&self) -> ::std::option::Option<&str> {
        self.control_set_name.as_deref()
    }
}
impl ::std::fmt::Debug for DelegationMetadata {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DelegationMetadata");
        formatter.field("id", &self.id);
        formatter.field("assessment_name", &"*** Sensitive Data Redacted ***");
        formatter.field("assessment_id", &self.assessment_id);
        formatter.field("status", &self.status);
        formatter.field("role_arn", &self.role_arn);
        formatter.field("creation_time", &self.creation_time);
        formatter.field("control_set_name", &self.control_set_name);
        formatter.finish()
    }
}
impl DelegationMetadata {
    /// Creates a new builder-style object to manufacture [`DelegationMetadata`](crate::types::DelegationMetadata).
    pub fn builder() -> crate::types::builders::DelegationMetadataBuilder {
        crate::types::builders::DelegationMetadataBuilder::default()
    }
}

/// A builder for [`DelegationMetadata`](crate::types::DelegationMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DelegationMetadataBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) assessment_name: ::std::option::Option<::std::string::String>,
    pub(crate) assessment_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DelegationStatus>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) control_set_name: ::std::option::Option<::std::string::String>,
}
impl DelegationMetadataBuilder {
    /// <p>The unique identifier for the delegation.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the delegation.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the delegation.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the associated assessment.</p>
    pub fn assessment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assessment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the associated assessment.</p>
    pub fn set_assessment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assessment_name = input;
        self
    }
    /// <p>The name of the associated assessment.</p>
    pub fn get_assessment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.assessment_name
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn assessment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assessment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn set_assessment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assessment_id = input;
        self
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn get_assessment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.assessment_id
    }
    /// <p>The current status of the delegation.</p>
    pub fn status(mut self, input: crate::types::DelegationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the delegation.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DelegationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the delegation.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DelegationStatus> {
        &self.status
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>Specifies when the delegation was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies when the delegation was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>Specifies when the delegation was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>Specifies the name of the control set that was delegated for review.</p>
    pub fn control_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the control set that was delegated for review.</p>
    pub fn set_control_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_set_name = input;
        self
    }
    /// <p>Specifies the name of the control set that was delegated for review.</p>
    pub fn get_control_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_set_name
    }
    /// Consumes the builder and constructs a [`DelegationMetadata`](crate::types::DelegationMetadata).
    pub fn build(self) -> crate::types::DelegationMetadata {
        crate::types::DelegationMetadata {
            id: self.id,
            assessment_name: self.assessment_name,
            assessment_id: self.assessment_id,
            status: self.status,
            role_arn: self.role_arn,
            creation_time: self.creation_time,
            control_set_name: self.control_set_name,
        }
    }
}
impl ::std::fmt::Debug for DelegationMetadataBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DelegationMetadataBuilder");
        formatter.field("id", &self.id);
        formatter.field("assessment_name", &"*** Sensitive Data Redacted ***");
        formatter.field("assessment_id", &self.assessment_id);
        formatter.field("status", &self.status);
        formatter.field("role_arn", &self.role_arn);
        formatter.field("creation_time", &self.creation_time);
        formatter.field("control_set_name", &self.control_set_name);
        formatter.finish()
    }
}

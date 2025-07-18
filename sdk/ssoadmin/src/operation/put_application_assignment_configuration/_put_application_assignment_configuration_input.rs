// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutApplicationAssignmentConfigurationInput {
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>If <code>AssignmentsRequired</code> is <code>true</code> (default value), users don’t have access to the application unless an assignment is created using the <a href="https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html">CreateApplicationAssignment API</a>. If <code>false</code>, all users have access to the application.</p>
    pub assignment_required: ::std::option::Option<bool>,
}
impl PutApplicationAssignmentConfigurationInput {
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>If <code>AssignmentsRequired</code> is <code>true</code> (default value), users don’t have access to the application unless an assignment is created using the <a href="https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html">CreateApplicationAssignment API</a>. If <code>false</code>, all users have access to the application.</p>
    pub fn assignment_required(&self) -> ::std::option::Option<bool> {
        self.assignment_required
    }
}
impl PutApplicationAssignmentConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutApplicationAssignmentConfigurationInput`](crate::operation::put_application_assignment_configuration::PutApplicationAssignmentConfigurationInput).
    pub fn builder() -> crate::operation::put_application_assignment_configuration::builders::PutApplicationAssignmentConfigurationInputBuilder {
        crate::operation::put_application_assignment_configuration::builders::PutApplicationAssignmentConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutApplicationAssignmentConfigurationInput`](crate::operation::put_application_assignment_configuration::PutApplicationAssignmentConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutApplicationAssignmentConfigurationInputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) assignment_required: ::std::option::Option<bool>,
}
impl PutApplicationAssignmentConfigurationInputBuilder {
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>If <code>AssignmentsRequired</code> is <code>true</code> (default value), users don’t have access to the application unless an assignment is created using the <a href="https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html">CreateApplicationAssignment API</a>. If <code>false</code>, all users have access to the application.</p>
    /// This field is required.
    pub fn assignment_required(mut self, input: bool) -> Self {
        self.assignment_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>AssignmentsRequired</code> is <code>true</code> (default value), users don’t have access to the application unless an assignment is created using the <a href="https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html">CreateApplicationAssignment API</a>. If <code>false</code>, all users have access to the application.</p>
    pub fn set_assignment_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.assignment_required = input;
        self
    }
    /// <p>If <code>AssignmentsRequired</code> is <code>true</code> (default value), users don’t have access to the application unless an assignment is created using the <a href="https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html">CreateApplicationAssignment API</a>. If <code>false</code>, all users have access to the application.</p>
    pub fn get_assignment_required(&self) -> &::std::option::Option<bool> {
        &self.assignment_required
    }
    /// Consumes the builder and constructs a [`PutApplicationAssignmentConfigurationInput`](crate::operation::put_application_assignment_configuration::PutApplicationAssignmentConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_application_assignment_configuration::PutApplicationAssignmentConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_application_assignment_configuration::PutApplicationAssignmentConfigurationInput {
                application_arn: self.application_arn,
                assignment_required: self.assignment_required,
            },
        )
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationAssignmentInput {
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
    /// <p>The entity type for which the assignment will be created.</p>
    pub principal_type: ::std::option::Option<crate::types::PrincipalType>,
}
impl DescribeApplicationAssignmentInput {
    /// <p>Specifies the ARN of the application. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn principal_type(&self) -> ::std::option::Option<&crate::types::PrincipalType> {
        self.principal_type.as_ref()
    }
}
impl DescribeApplicationAssignmentInput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationAssignmentInput`](crate::operation::describe_application_assignment::DescribeApplicationAssignmentInput).
    pub fn builder() -> crate::operation::describe_application_assignment::builders::DescribeApplicationAssignmentInputBuilder {
        crate::operation::describe_application_assignment::builders::DescribeApplicationAssignmentInputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationAssignmentInput`](crate::operation::describe_application_assignment::DescribeApplicationAssignmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationAssignmentInputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_type: ::std::option::Option<crate::types::PrincipalType>,
}
impl DescribeApplicationAssignmentInputBuilder {
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
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    /// This field is required.
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// <p>The entity type for which the assignment will be created.</p>
    /// This field is required.
    pub fn principal_type(mut self, input: crate::types::PrincipalType) -> Self {
        self.principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn set_principal_type(mut self, input: ::std::option::Option<crate::types::PrincipalType>) -> Self {
        self.principal_type = input;
        self
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn get_principal_type(&self) -> &::std::option::Option<crate::types::PrincipalType> {
        &self.principal_type
    }
    /// Consumes the builder and constructs a [`DescribeApplicationAssignmentInput`](crate::operation::describe_application_assignment::DescribeApplicationAssignmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_application_assignment::DescribeApplicationAssignmentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_application_assignment::DescribeApplicationAssignmentInput {
            application_arn: self.application_arn,
            principal_id: self.principal_id,
            principal_type: self.principal_type,
        })
    }
}

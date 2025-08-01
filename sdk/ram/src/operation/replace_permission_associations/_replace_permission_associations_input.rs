// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplacePermissionAssociationsInput {
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the managed permission that you want to replace.</p>
    pub from_permission_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies that you want to updated the permissions for only those resource shares that use the specified version of the managed permission.</p>
    pub from_permission_version: ::std::option::Option<i32>,
    /// <p>Specifies the ARN of the managed permission that you want to associate with resource shares in place of the one specified by <code>fromPerssionArn</code> and <code>fromPermissionVersion</code>.</p>
    /// <p>The operation always associates the version that is currently the default for the specified managed permission.</p>
    pub to_permission_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl ReplacePermissionAssociationsInput {
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the managed permission that you want to replace.</p>
    pub fn from_permission_arn(&self) -> ::std::option::Option<&str> {
        self.from_permission_arn.as_deref()
    }
    /// <p>Specifies that you want to updated the permissions for only those resource shares that use the specified version of the managed permission.</p>
    pub fn from_permission_version(&self) -> ::std::option::Option<i32> {
        self.from_permission_version
    }
    /// <p>Specifies the ARN of the managed permission that you want to associate with resource shares in place of the one specified by <code>fromPerssionArn</code> and <code>fromPermissionVersion</code>.</p>
    /// <p>The operation always associates the version that is currently the default for the specified managed permission.</p>
    pub fn to_permission_arn(&self) -> ::std::option::Option<&str> {
        self.to_permission_arn.as_deref()
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ReplacePermissionAssociationsInput {
    /// Creates a new builder-style object to manufacture [`ReplacePermissionAssociationsInput`](crate::operation::replace_permission_associations::ReplacePermissionAssociationsInput).
    pub fn builder() -> crate::operation::replace_permission_associations::builders::ReplacePermissionAssociationsInputBuilder {
        crate::operation::replace_permission_associations::builders::ReplacePermissionAssociationsInputBuilder::default()
    }
}

/// A builder for [`ReplacePermissionAssociationsInput`](crate::operation::replace_permission_associations::ReplacePermissionAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplacePermissionAssociationsInputBuilder {
    pub(crate) from_permission_arn: ::std::option::Option<::std::string::String>,
    pub(crate) from_permission_version: ::std::option::Option<i32>,
    pub(crate) to_permission_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl ReplacePermissionAssociationsInputBuilder {
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the managed permission that you want to replace.</p>
    /// This field is required.
    pub fn from_permission_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_permission_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the managed permission that you want to replace.</p>
    pub fn set_from_permission_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_permission_arn = input;
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of the managed permission that you want to replace.</p>
    pub fn get_from_permission_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_permission_arn
    }
    /// <p>Specifies that you want to updated the permissions for only those resource shares that use the specified version of the managed permission.</p>
    pub fn from_permission_version(mut self, input: i32) -> Self {
        self.from_permission_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies that you want to updated the permissions for only those resource shares that use the specified version of the managed permission.</p>
    pub fn set_from_permission_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.from_permission_version = input;
        self
    }
    /// <p>Specifies that you want to updated the permissions for only those resource shares that use the specified version of the managed permission.</p>
    pub fn get_from_permission_version(&self) -> &::std::option::Option<i32> {
        &self.from_permission_version
    }
    /// <p>Specifies the ARN of the managed permission that you want to associate with resource shares in place of the one specified by <code>fromPerssionArn</code> and <code>fromPermissionVersion</code>.</p>
    /// <p>The operation always associates the version that is currently the default for the specified managed permission.</p>
    /// This field is required.
    pub fn to_permission_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.to_permission_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the managed permission that you want to associate with resource shares in place of the one specified by <code>fromPerssionArn</code> and <code>fromPermissionVersion</code>.</p>
    /// <p>The operation always associates the version that is currently the default for the specified managed permission.</p>
    pub fn set_to_permission_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.to_permission_arn = input;
        self
    }
    /// <p>Specifies the ARN of the managed permission that you want to associate with resource shares in place of the one specified by <code>fromPerssionArn</code> and <code>fromPermissionVersion</code>.</p>
    /// <p>The operation always associates the version that is currently the default for the specified managed permission.</p>
    pub fn get_to_permission_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.to_permission_arn
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value.</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`ReplacePermissionAssociationsInput`](crate::operation::replace_permission_associations::ReplacePermissionAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::replace_permission_associations::ReplacePermissionAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::replace_permission_associations::ReplacePermissionAssociationsInput {
            from_permission_arn: self.from_permission_arn,
            from_permission_version: self.from_permission_version,
            to_permission_arn: self.to_permission_arn,
            client_token: self.client_token,
        })
    }
}

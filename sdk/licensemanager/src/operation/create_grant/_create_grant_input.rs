// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGrantInput {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Grant name.</p>
    pub grant_name: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub license_arn: ::std::option::Option<::std::string::String>,
    /// <p>The grant principals. You can specify one of the following as an Amazon Resource Name (ARN):</p>
    /// <ul>
    /// <li>
    /// <p>An Amazon Web Services account, which includes only the account specified.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organizational unit (OU), which includes all accounts in the OU.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organization, which will include all accounts across your organization.</p></li>
    /// </ul>
    pub principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Home Region of the grant.</p>
    pub home_region: ::std::option::Option<::std::string::String>,
    /// <p>Allowed operations for the grant.</p>
    pub allowed_operations: ::std::option::Option<::std::vec::Vec<crate::types::AllowedOperation>>,
    /// <p>Tags to add to the grant. For more information about tagging support in License Manager, see the <a href="https://docs.aws.amazon.com/license-manager/latest/APIReference/API_TagResource.html">TagResource</a> operation.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateGrantInput {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Grant name.</p>
    pub fn grant_name(&self) -> ::std::option::Option<&str> {
        self.grant_name.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn license_arn(&self) -> ::std::option::Option<&str> {
        self.license_arn.as_deref()
    }
    /// <p>The grant principals. You can specify one of the following as an Amazon Resource Name (ARN):</p>
    /// <ul>
    /// <li>
    /// <p>An Amazon Web Services account, which includes only the account specified.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organizational unit (OU), which includes all accounts in the OU.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organization, which will include all accounts across your organization.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.principals.is_none()`.
    pub fn principals(&self) -> &[::std::string::String] {
        self.principals.as_deref().unwrap_or_default()
    }
    /// <p>Home Region of the grant.</p>
    pub fn home_region(&self) -> ::std::option::Option<&str> {
        self.home_region.as_deref()
    }
    /// <p>Allowed operations for the grant.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_operations.is_none()`.
    pub fn allowed_operations(&self) -> &[crate::types::AllowedOperation] {
        self.allowed_operations.as_deref().unwrap_or_default()
    }
    /// <p>Tags to add to the grant. For more information about tagging support in License Manager, see the <a href="https://docs.aws.amazon.com/license-manager/latest/APIReference/API_TagResource.html">TagResource</a> operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateGrantInput {
    /// Creates a new builder-style object to manufacture [`CreateGrantInput`](crate::operation::create_grant::CreateGrantInput).
    pub fn builder() -> crate::operation::create_grant::builders::CreateGrantInputBuilder {
        crate::operation::create_grant::builders::CreateGrantInputBuilder::default()
    }
}

/// A builder for [`CreateGrantInput`](crate::operation::create_grant::CreateGrantInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGrantInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) grant_name: ::std::option::Option<::std::string::String>,
    pub(crate) license_arn: ::std::option::Option<::std::string::String>,
    pub(crate) principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) home_region: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_operations: ::std::option::Option<::std::vec::Vec<crate::types::AllowedOperation>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateGrantInputBuilder {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Grant name.</p>
    /// This field is required.
    pub fn grant_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Grant name.</p>
    pub fn set_grant_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_name = input;
        self
    }
    /// <p>Grant name.</p>
    pub fn get_grant_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_name
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    /// This field is required.
    pub fn license_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn set_license_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn get_license_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_arn
    }
    /// Appends an item to `principals`.
    ///
    /// To override the contents of this collection use [`set_principals`](Self::set_principals).
    ///
    /// <p>The grant principals. You can specify one of the following as an Amazon Resource Name (ARN):</p>
    /// <ul>
    /// <li>
    /// <p>An Amazon Web Services account, which includes only the account specified.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organizational unit (OU), which includes all accounts in the OU.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organization, which will include all accounts across your organization.</p></li>
    /// </ul>
    pub fn principals(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.principals.unwrap_or_default();
        v.push(input.into());
        self.principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>The grant principals. You can specify one of the following as an Amazon Resource Name (ARN):</p>
    /// <ul>
    /// <li>
    /// <p>An Amazon Web Services account, which includes only the account specified.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organizational unit (OU), which includes all accounts in the OU.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organization, which will include all accounts across your organization.</p></li>
    /// </ul>
    pub fn set_principals(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.principals = input;
        self
    }
    /// <p>The grant principals. You can specify one of the following as an Amazon Resource Name (ARN):</p>
    /// <ul>
    /// <li>
    /// <p>An Amazon Web Services account, which includes only the account specified.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organizational unit (OU), which includes all accounts in the OU.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>An organization, which will include all accounts across your organization.</p></li>
    /// </ul>
    pub fn get_principals(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.principals
    }
    /// <p>Home Region of the grant.</p>
    /// This field is required.
    pub fn home_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.home_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Home Region of the grant.</p>
    pub fn set_home_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.home_region = input;
        self
    }
    /// <p>Home Region of the grant.</p>
    pub fn get_home_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.home_region
    }
    /// Appends an item to `allowed_operations`.
    ///
    /// To override the contents of this collection use [`set_allowed_operations`](Self::set_allowed_operations).
    ///
    /// <p>Allowed operations for the grant.</p>
    pub fn allowed_operations(mut self, input: crate::types::AllowedOperation) -> Self {
        let mut v = self.allowed_operations.unwrap_or_default();
        v.push(input);
        self.allowed_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Allowed operations for the grant.</p>
    pub fn set_allowed_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AllowedOperation>>) -> Self {
        self.allowed_operations = input;
        self
    }
    /// <p>Allowed operations for the grant.</p>
    pub fn get_allowed_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AllowedOperation>> {
        &self.allowed_operations
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags to add to the grant. For more information about tagging support in License Manager, see the <a href="https://docs.aws.amazon.com/license-manager/latest/APIReference/API_TagResource.html">TagResource</a> operation.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags to add to the grant. For more information about tagging support in License Manager, see the <a href="https://docs.aws.amazon.com/license-manager/latest/APIReference/API_TagResource.html">TagResource</a> operation.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags to add to the grant. For more information about tagging support in License Manager, see the <a href="https://docs.aws.amazon.com/license-manager/latest/APIReference/API_TagResource.html">TagResource</a> operation.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateGrantInput`](crate::operation::create_grant::CreateGrantInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_grant::CreateGrantInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_grant::CreateGrantInput {
            client_token: self.client_token,
            grant_name: self.grant_name,
            license_arn: self.license_arn,
            principals: self.principals,
            home_region: self.home_region,
            allowed_operations: self.allowed_operations,
            tags: self.tags,
        })
    }
}

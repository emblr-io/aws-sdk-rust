// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAccessGrantsLocationInput {
    /// <p>The Amazon Web Services account ID of the S3 Access Grants instance.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The S3 path to the location that you are registering. The location scope can be the default S3 location <code>s3://</code>, the S3 path to a bucket <code>s3://<bucket></bucket></code>, or the S3 path to a bucket and prefix <code>s3://<bucket>
    /// /
    /// <prefix></prefix>
    /// </bucket></code>. A prefix in S3 is a string of characters at the beginning of an object key name used to organize the objects that you store in your S3 buckets. For example, object key names that start with the <code>engineering/</code> prefix or object key names that start with the <code>marketing/campaigns/</code> prefix.</p>
    pub location_scope: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role for the registered location. S3 Access Grants assumes this role to manage access to the registered location.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services resource tags that you are adding to the S3 Access Grants location. Each tag is a label consisting of a user-defined key and value. Tags can help you manage, identify, organize, search for, and filter resources.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAccessGrantsLocationInput {
    /// <p>The Amazon Web Services account ID of the S3 Access Grants instance.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The S3 path to the location that you are registering. The location scope can be the default S3 location <code>s3://</code>, the S3 path to a bucket <code>s3://<bucket></bucket></code>, or the S3 path to a bucket and prefix <code>s3://<bucket>
    /// /
    /// <prefix></prefix>
    /// </bucket></code>. A prefix in S3 is a string of characters at the beginning of an object key name used to organize the objects that you store in your S3 buckets. For example, object key names that start with the <code>engineering/</code> prefix or object key names that start with the <code>marketing/campaigns/</code> prefix.</p>
    pub fn location_scope(&self) -> ::std::option::Option<&str> {
        self.location_scope.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role for the registered location. S3 Access Grants assumes this role to manage access to the registered location.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
    /// <p>The Amazon Web Services resource tags that you are adding to the S3 Access Grants location. Each tag is a label consisting of a user-defined key and value. Tags can help you manage, identify, organize, search for, and filter resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateAccessGrantsLocationInput {
    /// Creates a new builder-style object to manufacture [`CreateAccessGrantsLocationInput`](crate::operation::create_access_grants_location::CreateAccessGrantsLocationInput).
    pub fn builder() -> crate::operation::create_access_grants_location::builders::CreateAccessGrantsLocationInputBuilder {
        crate::operation::create_access_grants_location::builders::CreateAccessGrantsLocationInputBuilder::default()
    }
}

/// A builder for [`CreateAccessGrantsLocationInput`](crate::operation::create_access_grants_location::CreateAccessGrantsLocationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAccessGrantsLocationInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) location_scope: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAccessGrantsLocationInputBuilder {
    /// <p>The Amazon Web Services account ID of the S3 Access Grants instance.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the S3 Access Grants instance.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the S3 Access Grants instance.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The S3 path to the location that you are registering. The location scope can be the default S3 location <code>s3://</code>, the S3 path to a bucket <code>s3://<bucket></bucket></code>, or the S3 path to a bucket and prefix <code>s3://<bucket>
    /// /
    /// <prefix></prefix>
    /// </bucket></code>. A prefix in S3 is a string of characters at the beginning of an object key name used to organize the objects that you store in your S3 buckets. For example, object key names that start with the <code>engineering/</code> prefix or object key names that start with the <code>marketing/campaigns/</code> prefix.</p>
    /// This field is required.
    pub fn location_scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_scope = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 path to the location that you are registering. The location scope can be the default S3 location <code>s3://</code>, the S3 path to a bucket <code>s3://<bucket></bucket></code>, or the S3 path to a bucket and prefix <code>s3://<bucket>
    /// /
    /// <prefix></prefix>
    /// </bucket></code>. A prefix in S3 is a string of characters at the beginning of an object key name used to organize the objects that you store in your S3 buckets. For example, object key names that start with the <code>engineering/</code> prefix or object key names that start with the <code>marketing/campaigns/</code> prefix.</p>
    pub fn set_location_scope(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_scope = input;
        self
    }
    /// <p>The S3 path to the location that you are registering. The location scope can be the default S3 location <code>s3://</code>, the S3 path to a bucket <code>s3://<bucket></bucket></code>, or the S3 path to a bucket and prefix <code>s3://<bucket>
    /// /
    /// <prefix></prefix>
    /// </bucket></code>. A prefix in S3 is a string of characters at the beginning of an object key name used to organize the objects that you store in your S3 buckets. For example, object key names that start with the <code>engineering/</code> prefix or object key names that start with the <code>marketing/campaigns/</code> prefix.</p>
    pub fn get_location_scope(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_scope
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role for the registered location. S3 Access Grants assumes this role to manage access to the registered location.</p>
    /// This field is required.
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role for the registered location. S3 Access Grants assumes this role to manage access to the registered location.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role for the registered location. S3 Access Grants assumes this role to manage access to the registered location.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The Amazon Web Services resource tags that you are adding to the S3 Access Grants location. Each tag is a label consisting of a user-defined key and value. Tags can help you manage, identify, organize, search for, and filter resources.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Web Services resource tags that you are adding to the S3 Access Grants location. Each tag is a label consisting of a user-defined key and value. Tags can help you manage, identify, organize, search for, and filter resources.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The Amazon Web Services resource tags that you are adding to the S3 Access Grants location. Each tag is a label consisting of a user-defined key and value. Tags can help you manage, identify, organize, search for, and filter resources.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateAccessGrantsLocationInput`](crate::operation::create_access_grants_location::CreateAccessGrantsLocationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_access_grants_location::CreateAccessGrantsLocationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_access_grants_location::CreateAccessGrantsLocationInput {
            account_id: self.account_id,
            location_scope: self.location_scope,
            iam_role_arn: self.iam_role_arn,
            tags: self.tags,
        })
    }
}

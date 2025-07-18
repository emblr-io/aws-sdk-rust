// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration options of the S3 Access Grants location. It contains the <code>S3SubPrefix</code> field. The grant scope, the data to which you are granting access, is the result of appending the <code>Subprefix</code> field to the scope of the registered location.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessGrantsLocationConfiguration {
    /// <p>The <code>S3SubPrefix</code> is appended to the location scope creating the grant scope. Use this field to narrow the scope of the grant to a subset of the location scope. This field is required if the location scope is the default location <code>s3://</code> because you cannot create a grant for all of your S3 data in the Region and must narrow the scope. For example, if the location scope is the default location <code>s3://</code>, the <code>S3SubPrefx</code> can be a <bucket-name>
    /// /*, so the full grant scope path would be
    /// <code>s3://<bucket-name>
    /// /*
    /// </bucket-name></code>. Or the
    /// <code>S3SubPrefx</code> can be
    /// <code><bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>, so the full grant scope path would be or
    /// <code>s3://<bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>.
    /// </bucket-name></p>
    /// <p>If the <code>S3SubPrefix</code> includes a prefix, append the wildcard character <code>*</code> after the prefix to indicate that you want to include all object key names in the bucket that start with that prefix.</p>
    pub s3_sub_prefix: ::std::option::Option<::std::string::String>,
}
impl AccessGrantsLocationConfiguration {
    /// <p>The <code>S3SubPrefix</code> is appended to the location scope creating the grant scope. Use this field to narrow the scope of the grant to a subset of the location scope. This field is required if the location scope is the default location <code>s3://</code> because you cannot create a grant for all of your S3 data in the Region and must narrow the scope. For example, if the location scope is the default location <code>s3://</code>, the <code>S3SubPrefx</code> can be a <bucket-name>
    /// /*, so the full grant scope path would be
    /// <code>s3://<bucket-name>
    /// /*
    /// </bucket-name></code>. Or the
    /// <code>S3SubPrefx</code> can be
    /// <code><bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>, so the full grant scope path would be or
    /// <code>s3://<bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>.
    /// </bucket-name></p>
    /// <p>If the <code>S3SubPrefix</code> includes a prefix, append the wildcard character <code>*</code> after the prefix to indicate that you want to include all object key names in the bucket that start with that prefix.</p>
    pub fn s3_sub_prefix(&self) -> ::std::option::Option<&str> {
        self.s3_sub_prefix.as_deref()
    }
}
impl AccessGrantsLocationConfiguration {
    /// Creates a new builder-style object to manufacture [`AccessGrantsLocationConfiguration`](crate::types::AccessGrantsLocationConfiguration).
    pub fn builder() -> crate::types::builders::AccessGrantsLocationConfigurationBuilder {
        crate::types::builders::AccessGrantsLocationConfigurationBuilder::default()
    }
}

/// A builder for [`AccessGrantsLocationConfiguration`](crate::types::AccessGrantsLocationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessGrantsLocationConfigurationBuilder {
    pub(crate) s3_sub_prefix: ::std::option::Option<::std::string::String>,
}
impl AccessGrantsLocationConfigurationBuilder {
    /// <p>The <code>S3SubPrefix</code> is appended to the location scope creating the grant scope. Use this field to narrow the scope of the grant to a subset of the location scope. This field is required if the location scope is the default location <code>s3://</code> because you cannot create a grant for all of your S3 data in the Region and must narrow the scope. For example, if the location scope is the default location <code>s3://</code>, the <code>S3SubPrefx</code> can be a <bucket-name>
    /// /*, so the full grant scope path would be
    /// <code>s3://<bucket-name>
    /// /*
    /// </bucket-name></code>. Or the
    /// <code>S3SubPrefx</code> can be
    /// <code><bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>, so the full grant scope path would be or
    /// <code>s3://<bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>.
    /// </bucket-name></p>
    /// <p>If the <code>S3SubPrefix</code> includes a prefix, append the wildcard character <code>*</code> after the prefix to indicate that you want to include all object key names in the bucket that start with that prefix.</p>
    pub fn s3_sub_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_sub_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>S3SubPrefix</code> is appended to the location scope creating the grant scope. Use this field to narrow the scope of the grant to a subset of the location scope. This field is required if the location scope is the default location <code>s3://</code> because you cannot create a grant for all of your S3 data in the Region and must narrow the scope. For example, if the location scope is the default location <code>s3://</code>, the <code>S3SubPrefx</code> can be a <bucket-name>
    /// /*, so the full grant scope path would be
    /// <code>s3://<bucket-name>
    /// /*
    /// </bucket-name></code>. Or the
    /// <code>S3SubPrefx</code> can be
    /// <code><bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>, so the full grant scope path would be or
    /// <code>s3://<bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>.
    /// </bucket-name></p>
    /// <p>If the <code>S3SubPrefix</code> includes a prefix, append the wildcard character <code>*</code> after the prefix to indicate that you want to include all object key names in the bucket that start with that prefix.</p>
    pub fn set_s3_sub_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_sub_prefix = input;
        self
    }
    /// <p>The <code>S3SubPrefix</code> is appended to the location scope creating the grant scope. Use this field to narrow the scope of the grant to a subset of the location scope. This field is required if the location scope is the default location <code>s3://</code> because you cannot create a grant for all of your S3 data in the Region and must narrow the scope. For example, if the location scope is the default location <code>s3://</code>, the <code>S3SubPrefx</code> can be a <bucket-name>
    /// /*, so the full grant scope path would be
    /// <code>s3://<bucket-name>
    /// /*
    /// </bucket-name></code>. Or the
    /// <code>S3SubPrefx</code> can be
    /// <code><bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>, so the full grant scope path would be or
    /// <code>s3://<bucket-name>
    /// /
    /// <prefix-name>
    /// *
    /// </prefix-name>
    /// </bucket-name></code>.
    /// </bucket-name></p>
    /// <p>If the <code>S3SubPrefix</code> includes a prefix, append the wildcard character <code>*</code> after the prefix to indicate that you want to include all object key names in the bucket that start with that prefix.</p>
    pub fn get_s3_sub_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_sub_prefix
    }
    /// Consumes the builder and constructs a [`AccessGrantsLocationConfiguration`](crate::types::AccessGrantsLocationConfiguration).
    pub fn build(self) -> crate::types::AccessGrantsLocationConfiguration {
        crate::types::AccessGrantsLocationConfiguration {
            s3_sub_prefix: self.s3_sub_prefix,
        }
    }
}

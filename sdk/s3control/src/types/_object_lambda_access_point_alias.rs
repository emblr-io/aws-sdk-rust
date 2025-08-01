// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The alias of an Object Lambda Access Point. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/olap-use.html#ol-access-points-alias">How to use a bucket-style alias for your S3 bucket Object Lambda Access Point</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectLambdaAccessPointAlias {
    /// <p>The alias value of the Object Lambda Access Point.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The status of the Object Lambda Access Point alias. If the status is <code>PROVISIONING</code>, the Object Lambda Access Point is provisioning the alias and the alias is not ready for use yet. If the status is <code>READY</code>, the Object Lambda Access Point alias is successfully provisioned and ready for use.</p>
    pub status: ::std::option::Option<crate::types::ObjectLambdaAccessPointAliasStatus>,
}
impl ObjectLambdaAccessPointAlias {
    /// <p>The alias value of the Object Lambda Access Point.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The status of the Object Lambda Access Point alias. If the status is <code>PROVISIONING</code>, the Object Lambda Access Point is provisioning the alias and the alias is not ready for use yet. If the status is <code>READY</code>, the Object Lambda Access Point alias is successfully provisioned and ready for use.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ObjectLambdaAccessPointAliasStatus> {
        self.status.as_ref()
    }
}
impl ObjectLambdaAccessPointAlias {
    /// Creates a new builder-style object to manufacture [`ObjectLambdaAccessPointAlias`](crate::types::ObjectLambdaAccessPointAlias).
    pub fn builder() -> crate::types::builders::ObjectLambdaAccessPointAliasBuilder {
        crate::types::builders::ObjectLambdaAccessPointAliasBuilder::default()
    }
}

/// A builder for [`ObjectLambdaAccessPointAlias`](crate::types::ObjectLambdaAccessPointAlias).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectLambdaAccessPointAliasBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ObjectLambdaAccessPointAliasStatus>,
}
impl ObjectLambdaAccessPointAliasBuilder {
    /// <p>The alias value of the Object Lambda Access Point.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias value of the Object Lambda Access Point.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The alias value of the Object Lambda Access Point.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The status of the Object Lambda Access Point alias. If the status is <code>PROVISIONING</code>, the Object Lambda Access Point is provisioning the alias and the alias is not ready for use yet. If the status is <code>READY</code>, the Object Lambda Access Point alias is successfully provisioned and ready for use.</p>
    pub fn status(mut self, input: crate::types::ObjectLambdaAccessPointAliasStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the Object Lambda Access Point alias. If the status is <code>PROVISIONING</code>, the Object Lambda Access Point is provisioning the alias and the alias is not ready for use yet. If the status is <code>READY</code>, the Object Lambda Access Point alias is successfully provisioned and ready for use.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ObjectLambdaAccessPointAliasStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the Object Lambda Access Point alias. If the status is <code>PROVISIONING</code>, the Object Lambda Access Point is provisioning the alias and the alias is not ready for use yet. If the status is <code>READY</code>, the Object Lambda Access Point alias is successfully provisioned and ready for use.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ObjectLambdaAccessPointAliasStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ObjectLambdaAccessPointAlias`](crate::types::ObjectLambdaAccessPointAlias).
    pub fn build(self) -> crate::types::ObjectLambdaAccessPointAlias {
        crate::types::ObjectLambdaAccessPointAlias {
            value: self.value,
            status: self.status,
        }
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UntagResourceInput {
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid value is <code>RDS</code>.</p>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
    /// <p>The Amazon RDS Performance Insights resource that the tags are added to. This value is an Amazon Resource Name (ARN). For information about creating an ARN, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing"> Constructing an RDS Amazon Resource Name (ARN)</a>.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The metadata assigned to an Amazon RDS Performance Insights resource consisting of a key-value pair.</p>
    pub tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInput {
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid value is <code>RDS</code>.</p>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
    /// <p>The Amazon RDS Performance Insights resource that the tags are added to. This value is an Amazon Resource Name (ARN). For information about creating an ARN, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing"> Constructing an RDS Amazon Resource Name (ARN)</a>.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The metadata assigned to an Amazon RDS Performance Insights resource consisting of a key-value pair.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_keys.is_none()`.
    pub fn tag_keys(&self) -> &[::std::string::String] {
        self.tag_keys.as_deref().unwrap_or_default()
    }
}
impl UntagResourceInput {
    /// Creates a new builder-style object to manufacture [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn builder() -> crate::operation::untag_resource::builders::UntagResourceInputBuilder {
        crate::operation::untag_resource::builders::UntagResourceInputBuilder::default()
    }
}

/// A builder for [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UntagResourceInputBuilder {
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInputBuilder {
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid value is <code>RDS</code>.</p>
    /// This field is required.
    pub fn service_type(mut self, input: crate::types::ServiceType) -> Self {
        self.service_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid value is <code>RDS</code>.</p>
    pub fn set_service_type(mut self, input: ::std::option::Option<crate::types::ServiceType>) -> Self {
        self.service_type = input;
        self
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid value is <code>RDS</code>.</p>
    pub fn get_service_type(&self) -> &::std::option::Option<crate::types::ServiceType> {
        &self.service_type
    }
    /// <p>The Amazon RDS Performance Insights resource that the tags are added to. This value is an Amazon Resource Name (ARN). For information about creating an ARN, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing"> Constructing an RDS Amazon Resource Name (ARN)</a>.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon RDS Performance Insights resource that the tags are added to. This value is an Amazon Resource Name (ARN). For information about creating an ARN, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing"> Constructing an RDS Amazon Resource Name (ARN)</a>.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon RDS Performance Insights resource that the tags are added to. This value is an Amazon Resource Name (ARN). For information about creating an ARN, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html#USER_Tagging.ARN.Constructing"> Constructing an RDS Amazon Resource Name (ARN)</a>.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Appends an item to `tag_keys`.
    ///
    /// To override the contents of this collection use [`set_tag_keys`](Self::set_tag_keys).
    ///
    /// <p>The metadata assigned to an Amazon RDS Performance Insights resource consisting of a key-value pair.</p>
    pub fn tag_keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_keys.unwrap_or_default();
        v.push(input.into());
        self.tag_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>The metadata assigned to an Amazon RDS Performance Insights resource consisting of a key-value pair.</p>
    pub fn set_tag_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_keys = input;
        self
    }
    /// <p>The metadata assigned to an Amazon RDS Performance Insights resource consisting of a key-value pair.</p>
    pub fn get_tag_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_keys
    }
    /// Consumes the builder and constructs a [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::untag_resource::UntagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::untag_resource::UntagResourceInput {
            service_type: self.service_type,
            resource_arn: self.resource_arn,
            tag_keys: self.tag_keys,
        })
    }
}

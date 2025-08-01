// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFeatureMetadataInput {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group containing the feature.</p>
    pub feature_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the feature.</p>
    pub feature_name: ::std::option::Option<::std::string::String>,
}
impl DescribeFeatureMetadataInput {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group containing the feature.</p>
    pub fn feature_group_name(&self) -> ::std::option::Option<&str> {
        self.feature_group_name.as_deref()
    }
    /// <p>The name of the feature.</p>
    pub fn feature_name(&self) -> ::std::option::Option<&str> {
        self.feature_name.as_deref()
    }
}
impl DescribeFeatureMetadataInput {
    /// Creates a new builder-style object to manufacture [`DescribeFeatureMetadataInput`](crate::operation::describe_feature_metadata::DescribeFeatureMetadataInput).
    pub fn builder() -> crate::operation::describe_feature_metadata::builders::DescribeFeatureMetadataInputBuilder {
        crate::operation::describe_feature_metadata::builders::DescribeFeatureMetadataInputBuilder::default()
    }
}

/// A builder for [`DescribeFeatureMetadataInput`](crate::operation::describe_feature_metadata::DescribeFeatureMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFeatureMetadataInputBuilder {
    pub(crate) feature_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) feature_name: ::std::option::Option<::std::string::String>,
}
impl DescribeFeatureMetadataInputBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group containing the feature.</p>
    /// This field is required.
    pub fn feature_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the feature group containing the feature.</p>
    pub fn set_feature_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature_group_name = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the feature group containing the feature.</p>
    pub fn get_feature_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature_group_name
    }
    /// <p>The name of the feature.</p>
    /// This field is required.
    pub fn feature_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the feature.</p>
    pub fn set_feature_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature_name = input;
        self
    }
    /// <p>The name of the feature.</p>
    pub fn get_feature_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature_name
    }
    /// Consumes the builder and constructs a [`DescribeFeatureMetadataInput`](crate::operation::describe_feature_metadata::DescribeFeatureMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_feature_metadata::DescribeFeatureMetadataInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_feature_metadata::DescribeFeatureMetadataInput {
            feature_group_name: self.feature_group_name,
            feature_name: self.feature_name,
        })
    }
}

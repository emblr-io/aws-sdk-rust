// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteFeatureInput {
    /// <p>The name or ARN of the project that contains the feature to delete.</p>
    pub project: ::std::option::Option<::std::string::String>,
    /// <p>The name of the feature to delete.</p>
    pub feature: ::std::option::Option<::std::string::String>,
}
impl DeleteFeatureInput {
    /// <p>The name or ARN of the project that contains the feature to delete.</p>
    pub fn project(&self) -> ::std::option::Option<&str> {
        self.project.as_deref()
    }
    /// <p>The name of the feature to delete.</p>
    pub fn feature(&self) -> ::std::option::Option<&str> {
        self.feature.as_deref()
    }
}
impl DeleteFeatureInput {
    /// Creates a new builder-style object to manufacture [`DeleteFeatureInput`](crate::operation::delete_feature::DeleteFeatureInput).
    pub fn builder() -> crate::operation::delete_feature::builders::DeleteFeatureInputBuilder {
        crate::operation::delete_feature::builders::DeleteFeatureInputBuilder::default()
    }
}

/// A builder for [`DeleteFeatureInput`](crate::operation::delete_feature::DeleteFeatureInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteFeatureInputBuilder {
    pub(crate) project: ::std::option::Option<::std::string::String>,
    pub(crate) feature: ::std::option::Option<::std::string::String>,
}
impl DeleteFeatureInputBuilder {
    /// <p>The name or ARN of the project that contains the feature to delete.</p>
    /// This field is required.
    pub fn project(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the project that contains the feature to delete.</p>
    pub fn set_project(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project = input;
        self
    }
    /// <p>The name or ARN of the project that contains the feature to delete.</p>
    pub fn get_project(&self) -> &::std::option::Option<::std::string::String> {
        &self.project
    }
    /// <p>The name of the feature to delete.</p>
    /// This field is required.
    pub fn feature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the feature to delete.</p>
    pub fn set_feature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature = input;
        self
    }
    /// <p>The name of the feature to delete.</p>
    pub fn get_feature(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature
    }
    /// Consumes the builder and constructs a [`DeleteFeatureInput`](crate::operation::delete_feature::DeleteFeatureInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_feature::DeleteFeatureInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_feature::DeleteFeatureInput {
            project: self.project,
            feature: self.feature,
        })
    }
}

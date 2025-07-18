// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the model metadata.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelMetadataSummary {
    /// <p>The machine learning domain of the model.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The machine learning framework of the model.</p>
    pub framework: ::std::option::Option<::std::string::String>,
    /// <p>The machine learning task of the model.</p>
    pub task: ::std::option::Option<::std::string::String>,
    /// <p>The name of the model.</p>
    pub model: ::std::option::Option<::std::string::String>,
    /// <p>The framework version of the model.</p>
    pub framework_version: ::std::option::Option<::std::string::String>,
}
impl ModelMetadataSummary {
    /// <p>The machine learning domain of the model.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The machine learning framework of the model.</p>
    pub fn framework(&self) -> ::std::option::Option<&str> {
        self.framework.as_deref()
    }
    /// <p>The machine learning task of the model.</p>
    pub fn task(&self) -> ::std::option::Option<&str> {
        self.task.as_deref()
    }
    /// <p>The name of the model.</p>
    pub fn model(&self) -> ::std::option::Option<&str> {
        self.model.as_deref()
    }
    /// <p>The framework version of the model.</p>
    pub fn framework_version(&self) -> ::std::option::Option<&str> {
        self.framework_version.as_deref()
    }
}
impl ModelMetadataSummary {
    /// Creates a new builder-style object to manufacture [`ModelMetadataSummary`](crate::types::ModelMetadataSummary).
    pub fn builder() -> crate::types::builders::ModelMetadataSummaryBuilder {
        crate::types::builders::ModelMetadataSummaryBuilder::default()
    }
}

/// A builder for [`ModelMetadataSummary`](crate::types::ModelMetadataSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelMetadataSummaryBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) framework: ::std::option::Option<::std::string::String>,
    pub(crate) task: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<::std::string::String>,
    pub(crate) framework_version: ::std::option::Option<::std::string::String>,
}
impl ModelMetadataSummaryBuilder {
    /// <p>The machine learning domain of the model.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The machine learning domain of the model.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The machine learning domain of the model.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The machine learning framework of the model.</p>
    /// This field is required.
    pub fn framework(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.framework = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The machine learning framework of the model.</p>
    pub fn set_framework(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.framework = input;
        self
    }
    /// <p>The machine learning framework of the model.</p>
    pub fn get_framework(&self) -> &::std::option::Option<::std::string::String> {
        &self.framework
    }
    /// <p>The machine learning task of the model.</p>
    /// This field is required.
    pub fn task(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The machine learning task of the model.</p>
    pub fn set_task(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task = input;
        self
    }
    /// <p>The machine learning task of the model.</p>
    pub fn get_task(&self) -> &::std::option::Option<::std::string::String> {
        &self.task
    }
    /// <p>The name of the model.</p>
    /// This field is required.
    pub fn model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the model.</p>
    pub fn set_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model = input;
        self
    }
    /// <p>The name of the model.</p>
    pub fn get_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.model
    }
    /// <p>The framework version of the model.</p>
    /// This field is required.
    pub fn framework_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.framework_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The framework version of the model.</p>
    pub fn set_framework_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.framework_version = input;
        self
    }
    /// <p>The framework version of the model.</p>
    pub fn get_framework_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.framework_version
    }
    /// Consumes the builder and constructs a [`ModelMetadataSummary`](crate::types::ModelMetadataSummary).
    pub fn build(self) -> crate::types::ModelMetadataSummary {
        crate::types::ModelMetadataSummary {
            domain: self.domain,
            framework: self.framework,
            task: self.task,
            model: self.model,
            framework_version: self.framework_version,
        }
    }
}

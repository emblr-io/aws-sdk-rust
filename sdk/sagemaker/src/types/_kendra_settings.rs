// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon SageMaker Canvas application setting where you configure document querying.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KendraSettings {
    /// <p>Describes whether the document querying feature is enabled or disabled in the Canvas application.</p>
    pub status: ::std::option::Option<crate::types::FeatureStatus>,
}
impl KendraSettings {
    /// <p>Describes whether the document querying feature is enabled or disabled in the Canvas application.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.status.as_ref()
    }
}
impl KendraSettings {
    /// Creates a new builder-style object to manufacture [`KendraSettings`](crate::types::KendraSettings).
    pub fn builder() -> crate::types::builders::KendraSettingsBuilder {
        crate::types::builders::KendraSettingsBuilder::default()
    }
}

/// A builder for [`KendraSettings`](crate::types::KendraSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KendraSettingsBuilder {
    pub(crate) status: ::std::option::Option<crate::types::FeatureStatus>,
}
impl KendraSettingsBuilder {
    /// <p>Describes whether the document querying feature is enabled or disabled in the Canvas application.</p>
    pub fn status(mut self, input: crate::types::FeatureStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes whether the document querying feature is enabled or disabled in the Canvas application.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Describes whether the document querying feature is enabled or disabled in the Canvas application.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`KendraSettings`](crate::types::KendraSettings).
    pub fn build(self) -> crate::types::KendraSettings {
        crate::types::KendraSettings { status: self.status }
    }
}

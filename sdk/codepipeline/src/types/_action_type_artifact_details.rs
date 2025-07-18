// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about parameters for artifacts associated with the action type, such as the minimum and maximum artifacts allowed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionTypeArtifactDetails {
    /// <p>The minimum number of artifacts that can be used with the action type. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub minimum_count: i32,
    /// <p>The maximum number of artifacts that can be used with the actiontype. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub maximum_count: i32,
}
impl ActionTypeArtifactDetails {
    /// <p>The minimum number of artifacts that can be used with the action type. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn minimum_count(&self) -> i32 {
        self.minimum_count
    }
    /// <p>The maximum number of artifacts that can be used with the actiontype. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn maximum_count(&self) -> i32 {
        self.maximum_count
    }
}
impl ActionTypeArtifactDetails {
    /// Creates a new builder-style object to manufacture [`ActionTypeArtifactDetails`](crate::types::ActionTypeArtifactDetails).
    pub fn builder() -> crate::types::builders::ActionTypeArtifactDetailsBuilder {
        crate::types::builders::ActionTypeArtifactDetailsBuilder::default()
    }
}

/// A builder for [`ActionTypeArtifactDetails`](crate::types::ActionTypeArtifactDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionTypeArtifactDetailsBuilder {
    pub(crate) minimum_count: ::std::option::Option<i32>,
    pub(crate) maximum_count: ::std::option::Option<i32>,
}
impl ActionTypeArtifactDetailsBuilder {
    /// <p>The minimum number of artifacts that can be used with the action type. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    /// This field is required.
    pub fn minimum_count(mut self, input: i32) -> Self {
        self.minimum_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of artifacts that can be used with the action type. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn set_minimum_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_count = input;
        self
    }
    /// <p>The minimum number of artifacts that can be used with the action type. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn get_minimum_count(&self) -> &::std::option::Option<i32> {
        &self.minimum_count
    }
    /// <p>The maximum number of artifacts that can be used with the actiontype. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    /// This field is required.
    pub fn maximum_count(mut self, input: i32) -> Self {
        self.maximum_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of artifacts that can be used with the actiontype. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn set_maximum_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_count = input;
        self
    }
    /// <p>The maximum number of artifacts that can be used with the actiontype. For example, you should specify a minimum and maximum of zero input artifacts for an action type with a category of <code>source</code>.</p>
    pub fn get_maximum_count(&self) -> &::std::option::Option<i32> {
        &self.maximum_count
    }
    /// Consumes the builder and constructs a [`ActionTypeArtifactDetails`](crate::types::ActionTypeArtifactDetails).
    pub fn build(self) -> crate::types::ActionTypeArtifactDetails {
        crate::types::ActionTypeArtifactDetails {
            minimum_count: self.minimum_count.unwrap_or_default(),
            maximum_count: self.maximum_count.unwrap_or_default(),
        }
    }
}

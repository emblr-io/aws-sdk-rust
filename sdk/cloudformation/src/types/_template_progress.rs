// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the progress of the template generation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateProgress {
    /// <p>The number of resources that succeeded the template generation.</p>
    pub resources_succeeded: ::std::option::Option<i32>,
    /// <p>The number of resources that failed the template generation.</p>
    pub resources_failed: ::std::option::Option<i32>,
    /// <p>The number of resources that are in-process for the template generation.</p>
    pub resources_processing: ::std::option::Option<i32>,
    /// <p>The number of resources that are still pending the template generation.</p>
    pub resources_pending: ::std::option::Option<i32>,
}
impl TemplateProgress {
    /// <p>The number of resources that succeeded the template generation.</p>
    pub fn resources_succeeded(&self) -> ::std::option::Option<i32> {
        self.resources_succeeded
    }
    /// <p>The number of resources that failed the template generation.</p>
    pub fn resources_failed(&self) -> ::std::option::Option<i32> {
        self.resources_failed
    }
    /// <p>The number of resources that are in-process for the template generation.</p>
    pub fn resources_processing(&self) -> ::std::option::Option<i32> {
        self.resources_processing
    }
    /// <p>The number of resources that are still pending the template generation.</p>
    pub fn resources_pending(&self) -> ::std::option::Option<i32> {
        self.resources_pending
    }
}
impl TemplateProgress {
    /// Creates a new builder-style object to manufacture [`TemplateProgress`](crate::types::TemplateProgress).
    pub fn builder() -> crate::types::builders::TemplateProgressBuilder {
        crate::types::builders::TemplateProgressBuilder::default()
    }
}

/// A builder for [`TemplateProgress`](crate::types::TemplateProgress).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateProgressBuilder {
    pub(crate) resources_succeeded: ::std::option::Option<i32>,
    pub(crate) resources_failed: ::std::option::Option<i32>,
    pub(crate) resources_processing: ::std::option::Option<i32>,
    pub(crate) resources_pending: ::std::option::Option<i32>,
}
impl TemplateProgressBuilder {
    /// <p>The number of resources that succeeded the template generation.</p>
    pub fn resources_succeeded(mut self, input: i32) -> Self {
        self.resources_succeeded = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of resources that succeeded the template generation.</p>
    pub fn set_resources_succeeded(mut self, input: ::std::option::Option<i32>) -> Self {
        self.resources_succeeded = input;
        self
    }
    /// <p>The number of resources that succeeded the template generation.</p>
    pub fn get_resources_succeeded(&self) -> &::std::option::Option<i32> {
        &self.resources_succeeded
    }
    /// <p>The number of resources that failed the template generation.</p>
    pub fn resources_failed(mut self, input: i32) -> Self {
        self.resources_failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of resources that failed the template generation.</p>
    pub fn set_resources_failed(mut self, input: ::std::option::Option<i32>) -> Self {
        self.resources_failed = input;
        self
    }
    /// <p>The number of resources that failed the template generation.</p>
    pub fn get_resources_failed(&self) -> &::std::option::Option<i32> {
        &self.resources_failed
    }
    /// <p>The number of resources that are in-process for the template generation.</p>
    pub fn resources_processing(mut self, input: i32) -> Self {
        self.resources_processing = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of resources that are in-process for the template generation.</p>
    pub fn set_resources_processing(mut self, input: ::std::option::Option<i32>) -> Self {
        self.resources_processing = input;
        self
    }
    /// <p>The number of resources that are in-process for the template generation.</p>
    pub fn get_resources_processing(&self) -> &::std::option::Option<i32> {
        &self.resources_processing
    }
    /// <p>The number of resources that are still pending the template generation.</p>
    pub fn resources_pending(mut self, input: i32) -> Self {
        self.resources_pending = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of resources that are still pending the template generation.</p>
    pub fn set_resources_pending(mut self, input: ::std::option::Option<i32>) -> Self {
        self.resources_pending = input;
        self
    }
    /// <p>The number of resources that are still pending the template generation.</p>
    pub fn get_resources_pending(&self) -> &::std::option::Option<i32> {
        &self.resources_pending
    }
    /// Consumes the builder and constructs a [`TemplateProgress`](crate::types::TemplateProgress).
    pub fn build(self) -> crate::types::TemplateProgress {
        crate::types::TemplateProgress {
            resources_succeeded: self.resources_succeeded,
            resources_failed: self.resources_failed,
            resources_processing: self.resources_processing,
            resources_pending: self.resources_pending,
        }
    }
}

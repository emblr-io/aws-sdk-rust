// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyClusterOutput {
    /// <p>The number of steps that can be executed concurrently.</p>
    pub step_concurrency_level: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl ModifyClusterOutput {
    /// <p>The number of steps that can be executed concurrently.</p>
    pub fn step_concurrency_level(&self) -> ::std::option::Option<i32> {
        self.step_concurrency_level
    }
}
impl ::aws_types::request_id::RequestId for ModifyClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyClusterOutput {
    /// Creates a new builder-style object to manufacture [`ModifyClusterOutput`](crate::operation::modify_cluster::ModifyClusterOutput).
    pub fn builder() -> crate::operation::modify_cluster::builders::ModifyClusterOutputBuilder {
        crate::operation::modify_cluster::builders::ModifyClusterOutputBuilder::default()
    }
}

/// A builder for [`ModifyClusterOutput`](crate::operation::modify_cluster::ModifyClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyClusterOutputBuilder {
    pub(crate) step_concurrency_level: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl ModifyClusterOutputBuilder {
    /// <p>The number of steps that can be executed concurrently.</p>
    pub fn step_concurrency_level(mut self, input: i32) -> Self {
        self.step_concurrency_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of steps that can be executed concurrently.</p>
    pub fn set_step_concurrency_level(mut self, input: ::std::option::Option<i32>) -> Self {
        self.step_concurrency_level = input;
        self
    }
    /// <p>The number of steps that can be executed concurrently.</p>
    pub fn get_step_concurrency_level(&self) -> &::std::option::Option<i32> {
        &self.step_concurrency_level
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyClusterOutput`](crate::operation::modify_cluster::ModifyClusterOutput).
    pub fn build(self) -> crate::operation::modify_cluster::ModifyClusterOutput {
        crate::operation::modify_cluster::ModifyClusterOutput {
            step_concurrency_level: self.step_concurrency_level,
            _request_id: self._request_id,
        }
    }
}

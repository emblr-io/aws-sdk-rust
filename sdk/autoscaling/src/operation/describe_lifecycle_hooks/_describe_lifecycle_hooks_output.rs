// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLifecycleHooksOutput {
    /// <p>The lifecycle hooks for the specified group.</p>
    pub lifecycle_hooks: ::std::option::Option<::std::vec::Vec<crate::types::LifecycleHook>>,
    _request_id: Option<String>,
}
impl DescribeLifecycleHooksOutput {
    /// <p>The lifecycle hooks for the specified group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lifecycle_hooks.is_none()`.
    pub fn lifecycle_hooks(&self) -> &[crate::types::LifecycleHook] {
        self.lifecycle_hooks.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLifecycleHooksOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLifecycleHooksOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLifecycleHooksOutput`](crate::operation::describe_lifecycle_hooks::DescribeLifecycleHooksOutput).
    pub fn builder() -> crate::operation::describe_lifecycle_hooks::builders::DescribeLifecycleHooksOutputBuilder {
        crate::operation::describe_lifecycle_hooks::builders::DescribeLifecycleHooksOutputBuilder::default()
    }
}

/// A builder for [`DescribeLifecycleHooksOutput`](crate::operation::describe_lifecycle_hooks::DescribeLifecycleHooksOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLifecycleHooksOutputBuilder {
    pub(crate) lifecycle_hooks: ::std::option::Option<::std::vec::Vec<crate::types::LifecycleHook>>,
    _request_id: Option<String>,
}
impl DescribeLifecycleHooksOutputBuilder {
    /// Appends an item to `lifecycle_hooks`.
    ///
    /// To override the contents of this collection use [`set_lifecycle_hooks`](Self::set_lifecycle_hooks).
    ///
    /// <p>The lifecycle hooks for the specified group.</p>
    pub fn lifecycle_hooks(mut self, input: crate::types::LifecycleHook) -> Self {
        let mut v = self.lifecycle_hooks.unwrap_or_default();
        v.push(input);
        self.lifecycle_hooks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The lifecycle hooks for the specified group.</p>
    pub fn set_lifecycle_hooks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LifecycleHook>>) -> Self {
        self.lifecycle_hooks = input;
        self
    }
    /// <p>The lifecycle hooks for the specified group.</p>
    pub fn get_lifecycle_hooks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LifecycleHook>> {
        &self.lifecycle_hooks
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeLifecycleHooksOutput`](crate::operation::describe_lifecycle_hooks::DescribeLifecycleHooksOutput).
    pub fn build(self) -> crate::operation::describe_lifecycle_hooks::DescribeLifecycleHooksOutput {
        crate::operation::describe_lifecycle_hooks::DescribeLifecycleHooksOutput {
            lifecycle_hooks: self.lifecycle_hooks,
            _request_id: self._request_id,
        }
    }
}

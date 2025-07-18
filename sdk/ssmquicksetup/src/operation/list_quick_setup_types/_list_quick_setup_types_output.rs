// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListQuickSetupTypesOutput {
    /// <p>An array of Quick Setup types.</p>
    pub quick_setup_type_list: ::std::option::Option<::std::vec::Vec<crate::types::QuickSetupTypeOutput>>,
    _request_id: Option<String>,
}
impl ListQuickSetupTypesOutput {
    /// <p>An array of Quick Setup types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.quick_setup_type_list.is_none()`.
    pub fn quick_setup_type_list(&self) -> &[crate::types::QuickSetupTypeOutput] {
        self.quick_setup_type_list.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListQuickSetupTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListQuickSetupTypesOutput {
    /// Creates a new builder-style object to manufacture [`ListQuickSetupTypesOutput`](crate::operation::list_quick_setup_types::ListQuickSetupTypesOutput).
    pub fn builder() -> crate::operation::list_quick_setup_types::builders::ListQuickSetupTypesOutputBuilder {
        crate::operation::list_quick_setup_types::builders::ListQuickSetupTypesOutputBuilder::default()
    }
}

/// A builder for [`ListQuickSetupTypesOutput`](crate::operation::list_quick_setup_types::ListQuickSetupTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListQuickSetupTypesOutputBuilder {
    pub(crate) quick_setup_type_list: ::std::option::Option<::std::vec::Vec<crate::types::QuickSetupTypeOutput>>,
    _request_id: Option<String>,
}
impl ListQuickSetupTypesOutputBuilder {
    /// Appends an item to `quick_setup_type_list`.
    ///
    /// To override the contents of this collection use [`set_quick_setup_type_list`](Self::set_quick_setup_type_list).
    ///
    /// <p>An array of Quick Setup types.</p>
    pub fn quick_setup_type_list(mut self, input: crate::types::QuickSetupTypeOutput) -> Self {
        let mut v = self.quick_setup_type_list.unwrap_or_default();
        v.push(input);
        self.quick_setup_type_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of Quick Setup types.</p>
    pub fn set_quick_setup_type_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::QuickSetupTypeOutput>>) -> Self {
        self.quick_setup_type_list = input;
        self
    }
    /// <p>An array of Quick Setup types.</p>
    pub fn get_quick_setup_type_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::QuickSetupTypeOutput>> {
        &self.quick_setup_type_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListQuickSetupTypesOutput`](crate::operation::list_quick_setup_types::ListQuickSetupTypesOutput).
    pub fn build(self) -> crate::operation::list_quick_setup_types::ListQuickSetupTypesOutput {
        crate::operation::list_quick_setup_types::ListQuickSetupTypesOutput {
            quick_setup_type_list: self.quick_setup_type_list,
            _request_id: self._request_id,
        }
    }
}

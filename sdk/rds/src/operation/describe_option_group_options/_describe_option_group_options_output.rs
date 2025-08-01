// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOptionGroupOptionsOutput {
    /// <p>List of available option group options.</p>
    pub option_group_options: ::std::option::Option<::std::vec::Vec<crate::types::OptionGroupOption>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeOptionGroupOptionsOutput {
    /// <p>List of available option group options.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.option_group_options.is_none()`.
    pub fn option_group_options(&self) -> &[crate::types::OptionGroupOption] {
        self.option_group_options.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeOptionGroupOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeOptionGroupOptionsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeOptionGroupOptionsOutput`](crate::operation::describe_option_group_options::DescribeOptionGroupOptionsOutput).
    pub fn builder() -> crate::operation::describe_option_group_options::builders::DescribeOptionGroupOptionsOutputBuilder {
        crate::operation::describe_option_group_options::builders::DescribeOptionGroupOptionsOutputBuilder::default()
    }
}

/// A builder for [`DescribeOptionGroupOptionsOutput`](crate::operation::describe_option_group_options::DescribeOptionGroupOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOptionGroupOptionsOutputBuilder {
    pub(crate) option_group_options: ::std::option::Option<::std::vec::Vec<crate::types::OptionGroupOption>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeOptionGroupOptionsOutputBuilder {
    /// Appends an item to `option_group_options`.
    ///
    /// To override the contents of this collection use [`set_option_group_options`](Self::set_option_group_options).
    ///
    /// <p>List of available option group options.</p>
    pub fn option_group_options(mut self, input: crate::types::OptionGroupOption) -> Self {
        let mut v = self.option_group_options.unwrap_or_default();
        v.push(input);
        self.option_group_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of available option group options.</p>
    pub fn set_option_group_options(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OptionGroupOption>>) -> Self {
        self.option_group_options = input;
        self
    }
    /// <p>List of available option group options.</p>
    pub fn get_option_group_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OptionGroupOption>> {
        &self.option_group_options
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeOptionGroupOptionsOutput`](crate::operation::describe_option_group_options::DescribeOptionGroupOptionsOutput).
    pub fn build(self) -> crate::operation::describe_option_group_options::DescribeOptionGroupOptionsOutput {
        crate::operation::describe_option_group_options::DescribeOptionGroupOptionsOutput {
            option_group_options: self.option_group_options,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}

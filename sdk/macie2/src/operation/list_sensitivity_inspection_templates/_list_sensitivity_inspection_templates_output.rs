// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSensitivityInspectionTemplatesOutput {
    /// <p>The string to use in a subsequent request to get the next page of results in a paginated response. This value is null if there are no additional pages.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array that specifies the unique identifier and name of the sensitivity inspection template for the account.</p>
    pub sensitivity_inspection_templates: ::std::option::Option<::std::vec::Vec<crate::types::SensitivityInspectionTemplatesEntry>>,
    _request_id: Option<String>,
}
impl ListSensitivityInspectionTemplatesOutput {
    /// <p>The string to use in a subsequent request to get the next page of results in a paginated response. This value is null if there are no additional pages.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array that specifies the unique identifier and name of the sensitivity inspection template for the account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sensitivity_inspection_templates.is_none()`.
    pub fn sensitivity_inspection_templates(&self) -> &[crate::types::SensitivityInspectionTemplatesEntry] {
        self.sensitivity_inspection_templates.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSensitivityInspectionTemplatesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSensitivityInspectionTemplatesOutput {
    /// Creates a new builder-style object to manufacture [`ListSensitivityInspectionTemplatesOutput`](crate::operation::list_sensitivity_inspection_templates::ListSensitivityInspectionTemplatesOutput).
    pub fn builder() -> crate::operation::list_sensitivity_inspection_templates::builders::ListSensitivityInspectionTemplatesOutputBuilder {
        crate::operation::list_sensitivity_inspection_templates::builders::ListSensitivityInspectionTemplatesOutputBuilder::default()
    }
}

/// A builder for [`ListSensitivityInspectionTemplatesOutput`](crate::operation::list_sensitivity_inspection_templates::ListSensitivityInspectionTemplatesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSensitivityInspectionTemplatesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sensitivity_inspection_templates: ::std::option::Option<::std::vec::Vec<crate::types::SensitivityInspectionTemplatesEntry>>,
    _request_id: Option<String>,
}
impl ListSensitivityInspectionTemplatesOutputBuilder {
    /// <p>The string to use in a subsequent request to get the next page of results in a paginated response. This value is null if there are no additional pages.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string to use in a subsequent request to get the next page of results in a paginated response. This value is null if there are no additional pages.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string to use in a subsequent request to get the next page of results in a paginated response. This value is null if there are no additional pages.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `sensitivity_inspection_templates`.
    ///
    /// To override the contents of this collection use [`set_sensitivity_inspection_templates`](Self::set_sensitivity_inspection_templates).
    ///
    /// <p>An array that specifies the unique identifier and name of the sensitivity inspection template for the account.</p>
    pub fn sensitivity_inspection_templates(mut self, input: crate::types::SensitivityInspectionTemplatesEntry) -> Self {
        let mut v = self.sensitivity_inspection_templates.unwrap_or_default();
        v.push(input);
        self.sensitivity_inspection_templates = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that specifies the unique identifier and name of the sensitivity inspection template for the account.</p>
    pub fn set_sensitivity_inspection_templates(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SensitivityInspectionTemplatesEntry>>,
    ) -> Self {
        self.sensitivity_inspection_templates = input;
        self
    }
    /// <p>An array that specifies the unique identifier and name of the sensitivity inspection template for the account.</p>
    pub fn get_sensitivity_inspection_templates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SensitivityInspectionTemplatesEntry>> {
        &self.sensitivity_inspection_templates
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSensitivityInspectionTemplatesOutput`](crate::operation::list_sensitivity_inspection_templates::ListSensitivityInspectionTemplatesOutput).
    pub fn build(self) -> crate::operation::list_sensitivity_inspection_templates::ListSensitivityInspectionTemplatesOutput {
        crate::operation::list_sensitivity_inspection_templates::ListSensitivityInspectionTemplatesOutput {
            next_token: self.next_token,
            sensitivity_inspection_templates: self.sensitivity_inspection_templates,
            _request_id: self._request_id,
        }
    }
}

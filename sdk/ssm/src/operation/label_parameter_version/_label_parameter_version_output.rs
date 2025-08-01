// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LabelParameterVersionOutput {
    /// <p>The label doesn't meet the requirements. For information about parameter label requirements, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html">Working with parameter labels</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub invalid_labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The version of the parameter that has been labeled.</p>
    pub parameter_version: i64,
    _request_id: Option<String>,
}
impl LabelParameterVersionOutput {
    /// <p>The label doesn't meet the requirements. For information about parameter label requirements, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html">Working with parameter labels</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.invalid_labels.is_none()`.
    pub fn invalid_labels(&self) -> &[::std::string::String] {
        self.invalid_labels.as_deref().unwrap_or_default()
    }
    /// <p>The version of the parameter that has been labeled.</p>
    pub fn parameter_version(&self) -> i64 {
        self.parameter_version
    }
}
impl ::aws_types::request_id::RequestId for LabelParameterVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl LabelParameterVersionOutput {
    /// Creates a new builder-style object to manufacture [`LabelParameterVersionOutput`](crate::operation::label_parameter_version::LabelParameterVersionOutput).
    pub fn builder() -> crate::operation::label_parameter_version::builders::LabelParameterVersionOutputBuilder {
        crate::operation::label_parameter_version::builders::LabelParameterVersionOutputBuilder::default()
    }
}

/// A builder for [`LabelParameterVersionOutput`](crate::operation::label_parameter_version::LabelParameterVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LabelParameterVersionOutputBuilder {
    pub(crate) invalid_labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) parameter_version: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl LabelParameterVersionOutputBuilder {
    /// Appends an item to `invalid_labels`.
    ///
    /// To override the contents of this collection use [`set_invalid_labels`](Self::set_invalid_labels).
    ///
    /// <p>The label doesn't meet the requirements. For information about parameter label requirements, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html">Working with parameter labels</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn invalid_labels(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.invalid_labels.unwrap_or_default();
        v.push(input.into());
        self.invalid_labels = ::std::option::Option::Some(v);
        self
    }
    /// <p>The label doesn't meet the requirements. For information about parameter label requirements, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html">Working with parameter labels</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_invalid_labels(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.invalid_labels = input;
        self
    }
    /// <p>The label doesn't meet the requirements. For information about parameter label requirements, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html">Working with parameter labels</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_invalid_labels(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.invalid_labels
    }
    /// <p>The version of the parameter that has been labeled.</p>
    pub fn parameter_version(mut self, input: i64) -> Self {
        self.parameter_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the parameter that has been labeled.</p>
    pub fn set_parameter_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.parameter_version = input;
        self
    }
    /// <p>The version of the parameter that has been labeled.</p>
    pub fn get_parameter_version(&self) -> &::std::option::Option<i64> {
        &self.parameter_version
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`LabelParameterVersionOutput`](crate::operation::label_parameter_version::LabelParameterVersionOutput).
    pub fn build(self) -> crate::operation::label_parameter_version::LabelParameterVersionOutput {
        crate::operation::label_parameter_version::LabelParameterVersionOutput {
            invalid_labels: self.invalid_labels,
            parameter_version: self.parameter_version.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}

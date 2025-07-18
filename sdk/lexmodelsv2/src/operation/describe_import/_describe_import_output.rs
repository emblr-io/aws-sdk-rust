// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeImportOutput {
    /// <p>The unique identifier of the described import.</p>
    pub import_id: ::std::option::Option<::std::string::String>,
    /// <p>The specifications of the imported bot, bot locale, or custom vocabulary.</p>
    pub resource_specification: ::std::option::Option<crate::types::ImportResourceSpecification>,
    /// <p>The unique identifier that Amazon Lex assigned to the resource created by the import.</p>
    pub imported_resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the imported resource.</p>
    pub imported_resource_name: ::std::option::Option<::std::string::String>,
    /// <p>The strategy used when there was a name conflict between the imported resource and an existing resource. When the merge strategy is <code>FailOnConflict</code> existing resources are not overwritten and the import fails.</p>
    pub merge_strategy: ::std::option::Option<crate::types::MergeStrategy>,
    /// <p>The status of the import process. When the status is <code>Completed</code> the resource is imported and ready for use.</p>
    pub import_status: ::std::option::Option<crate::types::ImportStatus>,
    /// <p>If the <code>importStatus</code> field is <code>Failed</code>, this provides one or more reasons for the failure.</p>
    pub failure_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The date and time that the import was created.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the import was last updated.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeImportOutput {
    /// <p>The unique identifier of the described import.</p>
    pub fn import_id(&self) -> ::std::option::Option<&str> {
        self.import_id.as_deref()
    }
    /// <p>The specifications of the imported bot, bot locale, or custom vocabulary.</p>
    pub fn resource_specification(&self) -> ::std::option::Option<&crate::types::ImportResourceSpecification> {
        self.resource_specification.as_ref()
    }
    /// <p>The unique identifier that Amazon Lex assigned to the resource created by the import.</p>
    pub fn imported_resource_id(&self) -> ::std::option::Option<&str> {
        self.imported_resource_id.as_deref()
    }
    /// <p>The name of the imported resource.</p>
    pub fn imported_resource_name(&self) -> ::std::option::Option<&str> {
        self.imported_resource_name.as_deref()
    }
    /// <p>The strategy used when there was a name conflict between the imported resource and an existing resource. When the merge strategy is <code>FailOnConflict</code> existing resources are not overwritten and the import fails.</p>
    pub fn merge_strategy(&self) -> ::std::option::Option<&crate::types::MergeStrategy> {
        self.merge_strategy.as_ref()
    }
    /// <p>The status of the import process. When the status is <code>Completed</code> the resource is imported and ready for use.</p>
    pub fn import_status(&self) -> ::std::option::Option<&crate::types::ImportStatus> {
        self.import_status.as_ref()
    }
    /// <p>If the <code>importStatus</code> field is <code>Failed</code>, this provides one or more reasons for the failure.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failure_reasons.is_none()`.
    pub fn failure_reasons(&self) -> &[::std::string::String] {
        self.failure_reasons.as_deref().unwrap_or_default()
    }
    /// <p>The date and time that the import was created.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The date and time that the import was last updated.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeImportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeImportOutput {
    /// Creates a new builder-style object to manufacture [`DescribeImportOutput`](crate::operation::describe_import::DescribeImportOutput).
    pub fn builder() -> crate::operation::describe_import::builders::DescribeImportOutputBuilder {
        crate::operation::describe_import::builders::DescribeImportOutputBuilder::default()
    }
}

/// A builder for [`DescribeImportOutput`](crate::operation::describe_import::DescribeImportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeImportOutputBuilder {
    pub(crate) import_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_specification: ::std::option::Option<crate::types::ImportResourceSpecification>,
    pub(crate) imported_resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) imported_resource_name: ::std::option::Option<::std::string::String>,
    pub(crate) merge_strategy: ::std::option::Option<crate::types::MergeStrategy>,
    pub(crate) import_status: ::std::option::Option<crate::types::ImportStatus>,
    pub(crate) failure_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeImportOutputBuilder {
    /// <p>The unique identifier of the described import.</p>
    pub fn import_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.import_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the described import.</p>
    pub fn set_import_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.import_id = input;
        self
    }
    /// <p>The unique identifier of the described import.</p>
    pub fn get_import_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.import_id
    }
    /// <p>The specifications of the imported bot, bot locale, or custom vocabulary.</p>
    pub fn resource_specification(mut self, input: crate::types::ImportResourceSpecification) -> Self {
        self.resource_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specifications of the imported bot, bot locale, or custom vocabulary.</p>
    pub fn set_resource_specification(mut self, input: ::std::option::Option<crate::types::ImportResourceSpecification>) -> Self {
        self.resource_specification = input;
        self
    }
    /// <p>The specifications of the imported bot, bot locale, or custom vocabulary.</p>
    pub fn get_resource_specification(&self) -> &::std::option::Option<crate::types::ImportResourceSpecification> {
        &self.resource_specification
    }
    /// <p>The unique identifier that Amazon Lex assigned to the resource created by the import.</p>
    pub fn imported_resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.imported_resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier that Amazon Lex assigned to the resource created by the import.</p>
    pub fn set_imported_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.imported_resource_id = input;
        self
    }
    /// <p>The unique identifier that Amazon Lex assigned to the resource created by the import.</p>
    pub fn get_imported_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.imported_resource_id
    }
    /// <p>The name of the imported resource.</p>
    pub fn imported_resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.imported_resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the imported resource.</p>
    pub fn set_imported_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.imported_resource_name = input;
        self
    }
    /// <p>The name of the imported resource.</p>
    pub fn get_imported_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.imported_resource_name
    }
    /// <p>The strategy used when there was a name conflict between the imported resource and an existing resource. When the merge strategy is <code>FailOnConflict</code> existing resources are not overwritten and the import fails.</p>
    pub fn merge_strategy(mut self, input: crate::types::MergeStrategy) -> Self {
        self.merge_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The strategy used when there was a name conflict between the imported resource and an existing resource. When the merge strategy is <code>FailOnConflict</code> existing resources are not overwritten and the import fails.</p>
    pub fn set_merge_strategy(mut self, input: ::std::option::Option<crate::types::MergeStrategy>) -> Self {
        self.merge_strategy = input;
        self
    }
    /// <p>The strategy used when there was a name conflict between the imported resource and an existing resource. When the merge strategy is <code>FailOnConflict</code> existing resources are not overwritten and the import fails.</p>
    pub fn get_merge_strategy(&self) -> &::std::option::Option<crate::types::MergeStrategy> {
        &self.merge_strategy
    }
    /// <p>The status of the import process. When the status is <code>Completed</code> the resource is imported and ready for use.</p>
    pub fn import_status(mut self, input: crate::types::ImportStatus) -> Self {
        self.import_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the import process. When the status is <code>Completed</code> the resource is imported and ready for use.</p>
    pub fn set_import_status(mut self, input: ::std::option::Option<crate::types::ImportStatus>) -> Self {
        self.import_status = input;
        self
    }
    /// <p>The status of the import process. When the status is <code>Completed</code> the resource is imported and ready for use.</p>
    pub fn get_import_status(&self) -> &::std::option::Option<crate::types::ImportStatus> {
        &self.import_status
    }
    /// Appends an item to `failure_reasons`.
    ///
    /// To override the contents of this collection use [`set_failure_reasons`](Self::set_failure_reasons).
    ///
    /// <p>If the <code>importStatus</code> field is <code>Failed</code>, this provides one or more reasons for the failure.</p>
    pub fn failure_reasons(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.failure_reasons.unwrap_or_default();
        v.push(input.into());
        self.failure_reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>If the <code>importStatus</code> field is <code>Failed</code>, this provides one or more reasons for the failure.</p>
    pub fn set_failure_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.failure_reasons = input;
        self
    }
    /// <p>If the <code>importStatus</code> field is <code>Failed</code>, this provides one or more reasons for the failure.</p>
    pub fn get_failure_reasons(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.failure_reasons
    }
    /// <p>The date and time that the import was created.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the import was created.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The date and time that the import was created.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The date and time that the import was last updated.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the import was last updated.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The date and time that the import was last updated.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeImportOutput`](crate::operation::describe_import::DescribeImportOutput).
    pub fn build(self) -> crate::operation::describe_import::DescribeImportOutput {
        crate::operation::describe_import::DescribeImportOutput {
            import_id: self.import_id,
            resource_specification: self.resource_specification,
            imported_resource_id: self.imported_resource_id,
            imported_resource_name: self.imported_resource_name,
            merge_strategy: self.merge_strategy,
            import_status: self.import_status,
            failure_reasons: self.failure_reasons,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            _request_id: self._request_id,
        }
    }
}

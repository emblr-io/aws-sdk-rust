// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Used as the request parameter in the <code>ListAssessmentTemplates</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssessmentTemplateFilter {
    /// <p>For a record to match a filter, an explicit value or a string that contains a wildcard that is specified for this data type property must match the value of the <b>assessmentTemplateName</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub name_pattern: ::std::option::Option<::std::string::String>,
    /// <p>For a record to match a filter, the value specified for this data type property must inclusively match any value between the specified minimum and maximum values of the <b>durationInSeconds</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub duration_range: ::std::option::Option<crate::types::DurationRange>,
    /// <p>For a record to match a filter, the values that are specified for this data type property must be contained in the list of values of the <b>rulesPackageArns</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub rules_package_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AssessmentTemplateFilter {
    /// <p>For a record to match a filter, an explicit value or a string that contains a wildcard that is specified for this data type property must match the value of the <b>assessmentTemplateName</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn name_pattern(&self) -> ::std::option::Option<&str> {
        self.name_pattern.as_deref()
    }
    /// <p>For a record to match a filter, the value specified for this data type property must inclusively match any value between the specified minimum and maximum values of the <b>durationInSeconds</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn duration_range(&self) -> ::std::option::Option<&crate::types::DurationRange> {
        self.duration_range.as_ref()
    }
    /// <p>For a record to match a filter, the values that are specified for this data type property must be contained in the list of values of the <b>rulesPackageArns</b> property of the <code>AssessmentTemplate</code> data type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules_package_arns.is_none()`.
    pub fn rules_package_arns(&self) -> &[::std::string::String] {
        self.rules_package_arns.as_deref().unwrap_or_default()
    }
}
impl AssessmentTemplateFilter {
    /// Creates a new builder-style object to manufacture [`AssessmentTemplateFilter`](crate::types::AssessmentTemplateFilter).
    pub fn builder() -> crate::types::builders::AssessmentTemplateFilterBuilder {
        crate::types::builders::AssessmentTemplateFilterBuilder::default()
    }
}

/// A builder for [`AssessmentTemplateFilter`](crate::types::AssessmentTemplateFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssessmentTemplateFilterBuilder {
    pub(crate) name_pattern: ::std::option::Option<::std::string::String>,
    pub(crate) duration_range: ::std::option::Option<crate::types::DurationRange>,
    pub(crate) rules_package_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AssessmentTemplateFilterBuilder {
    /// <p>For a record to match a filter, an explicit value or a string that contains a wildcard that is specified for this data type property must match the value of the <b>assessmentTemplateName</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn name_pattern(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name_pattern = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For a record to match a filter, an explicit value or a string that contains a wildcard that is specified for this data type property must match the value of the <b>assessmentTemplateName</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn set_name_pattern(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name_pattern = input;
        self
    }
    /// <p>For a record to match a filter, an explicit value or a string that contains a wildcard that is specified for this data type property must match the value of the <b>assessmentTemplateName</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn get_name_pattern(&self) -> &::std::option::Option<::std::string::String> {
        &self.name_pattern
    }
    /// <p>For a record to match a filter, the value specified for this data type property must inclusively match any value between the specified minimum and maximum values of the <b>durationInSeconds</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn duration_range(mut self, input: crate::types::DurationRange) -> Self {
        self.duration_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a record to match a filter, the value specified for this data type property must inclusively match any value between the specified minimum and maximum values of the <b>durationInSeconds</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn set_duration_range(mut self, input: ::std::option::Option<crate::types::DurationRange>) -> Self {
        self.duration_range = input;
        self
    }
    /// <p>For a record to match a filter, the value specified for this data type property must inclusively match any value between the specified minimum and maximum values of the <b>durationInSeconds</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn get_duration_range(&self) -> &::std::option::Option<crate::types::DurationRange> {
        &self.duration_range
    }
    /// Appends an item to `rules_package_arns`.
    ///
    /// To override the contents of this collection use [`set_rules_package_arns`](Self::set_rules_package_arns).
    ///
    /// <p>For a record to match a filter, the values that are specified for this data type property must be contained in the list of values of the <b>rulesPackageArns</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn rules_package_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.rules_package_arns.unwrap_or_default();
        v.push(input.into());
        self.rules_package_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>For a record to match a filter, the values that are specified for this data type property must be contained in the list of values of the <b>rulesPackageArns</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn set_rules_package_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.rules_package_arns = input;
        self
    }
    /// <p>For a record to match a filter, the values that are specified for this data type property must be contained in the list of values of the <b>rulesPackageArns</b> property of the <code>AssessmentTemplate</code> data type.</p>
    pub fn get_rules_package_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.rules_package_arns
    }
    /// Consumes the builder and constructs a [`AssessmentTemplateFilter`](crate::types::AssessmentTemplateFilter).
    pub fn build(self) -> crate::types::AssessmentTemplateFilter {
        crate::types::AssessmentTemplateFilter {
            name_pattern: self.name_pattern,
            duration_range: self.duration_range,
            rules_package_arns: self.rules_package_arns,
        }
    }
}

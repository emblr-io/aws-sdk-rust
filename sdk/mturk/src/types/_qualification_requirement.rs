// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The QualificationRequirement data structure describes a Qualification that a Worker must have before the Worker is allowed to accept a HIT. A requirement may optionally state that a Worker must have the Qualification in order to preview the HIT, or see the HIT in search results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QualificationRequirement {
    /// <p>The ID of the Qualification type for the requirement.</p>
    pub qualification_type_id: ::std::string::String,
    /// <p>The kind of comparison to make against a Qualification's value. You can compare a Qualification's value to an IntegerValue to see if it is LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, EqualTo, or NotEqualTo the IntegerValue. You can compare it to a LocaleValue to see if it is EqualTo, or NotEqualTo the LocaleValue. You can check to see if the value is In or NotIn a set of IntegerValue or LocaleValue values. Lastly, a Qualification requirement can also test if a Qualification Exists or DoesNotExist in the user's profile, regardless of its value.</p>
    pub comparator: crate::types::Comparator,
    /// <p>The integer value to compare against the Qualification's value. IntegerValue must not be present if Comparator is Exists or DoesNotExist. IntegerValue can only be used if the Qualification type has an integer value; it cannot be used with the Worker_Locale QualificationType ID. When performing a set comparison by using the In or the NotIn comparator, you can use up to 15 IntegerValue elements in a QualificationRequirement data structure.</p>
    pub integer_values: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>The locale value to compare against the Qualification's value. The local value must be a valid ISO 3166 country code or supports ISO 3166-2 subdivisions. LocaleValue can only be used with a Worker_Locale QualificationType ID. LocaleValue can only be used with the EqualTo, NotEqualTo, In, and NotIn comparators. You must only use a single LocaleValue element when using the EqualTo or NotEqualTo comparators. When performing a set comparison by using the In or the NotIn comparator, you can use up to 30 LocaleValue elements in a QualificationRequirement data structure.</p>
    pub locale_values: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>,
    /// <p>DEPRECATED: Use the <code>ActionsGuarded</code> field instead. If RequiredToPreview is true, the question data for the HIT will not be shown when a Worker whose Qualifications do not meet this requirement tries to preview the HIT. That is, a Worker's Qualifications must meet all of the requirements for which RequiredToPreview is true in order to preview the HIT. If a Worker meets all of the requirements where RequiredToPreview is true (or if there are no such requirements), but does not meet all of the requirements for the HIT, the Worker will be allowed to preview the HIT's question data, but will not be allowed to accept and complete the HIT. The default is false. This should not be used in combination with the <code>ActionsGuarded</code> field.</p>
    #[deprecated]
    pub required_to_preview: ::std::option::Option<bool>,
    /// <p>Setting this attribute prevents Workers whose Qualifications do not meet this QualificationRequirement from taking the specified action. Valid arguments include "Accept" (Worker cannot accept the HIT, but can preview the HIT and see it in their search results), "PreviewAndAccept" (Worker cannot accept or preview the HIT, but can see the HIT in their search results), and "DiscoverPreviewAndAccept" (Worker cannot accept, preview, or see the HIT in their search results). It's possible for you to create a HIT with multiple QualificationRequirements (which can have different values for the ActionGuarded attribute). In this case, the Worker is only permitted to perform an action when they have met all QualificationRequirements guarding the action. The actions in the order of least restrictive to most restrictive are Discover, Preview and Accept. For example, if a Worker meets all QualificationRequirements that are set to DiscoverPreviewAndAccept, but do not meet all requirements that are set with PreviewAndAccept, then the Worker will be able to Discover, i.e. see the HIT in their search result, but will not be able to Preview or Accept the HIT. ActionsGuarded should not be used in combination with the <code>RequiredToPreview</code> field.</p>
    pub actions_guarded: ::std::option::Option<crate::types::HitAccessActions>,
}
impl QualificationRequirement {
    /// <p>The ID of the Qualification type for the requirement.</p>
    pub fn qualification_type_id(&self) -> &str {
        use std::ops::Deref;
        self.qualification_type_id.deref()
    }
    /// <p>The kind of comparison to make against a Qualification's value. You can compare a Qualification's value to an IntegerValue to see if it is LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, EqualTo, or NotEqualTo the IntegerValue. You can compare it to a LocaleValue to see if it is EqualTo, or NotEqualTo the LocaleValue. You can check to see if the value is In or NotIn a set of IntegerValue or LocaleValue values. Lastly, a Qualification requirement can also test if a Qualification Exists or DoesNotExist in the user's profile, regardless of its value.</p>
    pub fn comparator(&self) -> &crate::types::Comparator {
        &self.comparator
    }
    /// <p>The integer value to compare against the Qualification's value. IntegerValue must not be present if Comparator is Exists or DoesNotExist. IntegerValue can only be used if the Qualification type has an integer value; it cannot be used with the Worker_Locale QualificationType ID. When performing a set comparison by using the In or the NotIn comparator, you can use up to 15 IntegerValue elements in a QualificationRequirement data structure.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.integer_values.is_none()`.
    pub fn integer_values(&self) -> &[i32] {
        self.integer_values.as_deref().unwrap_or_default()
    }
    /// <p>The locale value to compare against the Qualification's value. The local value must be a valid ISO 3166 country code or supports ISO 3166-2 subdivisions. LocaleValue can only be used with a Worker_Locale QualificationType ID. LocaleValue can only be used with the EqualTo, NotEqualTo, In, and NotIn comparators. You must only use a single LocaleValue element when using the EqualTo or NotEqualTo comparators. When performing a set comparison by using the In or the NotIn comparator, you can use up to 30 LocaleValue elements in a QualificationRequirement data structure.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.locale_values.is_none()`.
    pub fn locale_values(&self) -> &[crate::types::Locale] {
        self.locale_values.as_deref().unwrap_or_default()
    }
    /// <p>DEPRECATED: Use the <code>ActionsGuarded</code> field instead. If RequiredToPreview is true, the question data for the HIT will not be shown when a Worker whose Qualifications do not meet this requirement tries to preview the HIT. That is, a Worker's Qualifications must meet all of the requirements for which RequiredToPreview is true in order to preview the HIT. If a Worker meets all of the requirements where RequiredToPreview is true (or if there are no such requirements), but does not meet all of the requirements for the HIT, the Worker will be allowed to preview the HIT's question data, but will not be allowed to accept and complete the HIT. The default is false. This should not be used in combination with the <code>ActionsGuarded</code> field.</p>
    #[deprecated]
    pub fn required_to_preview(&self) -> ::std::option::Option<bool> {
        self.required_to_preview
    }
    /// <p>Setting this attribute prevents Workers whose Qualifications do not meet this QualificationRequirement from taking the specified action. Valid arguments include "Accept" (Worker cannot accept the HIT, but can preview the HIT and see it in their search results), "PreviewAndAccept" (Worker cannot accept or preview the HIT, but can see the HIT in their search results), and "DiscoverPreviewAndAccept" (Worker cannot accept, preview, or see the HIT in their search results). It's possible for you to create a HIT with multiple QualificationRequirements (which can have different values for the ActionGuarded attribute). In this case, the Worker is only permitted to perform an action when they have met all QualificationRequirements guarding the action. The actions in the order of least restrictive to most restrictive are Discover, Preview and Accept. For example, if a Worker meets all QualificationRequirements that are set to DiscoverPreviewAndAccept, but do not meet all requirements that are set with PreviewAndAccept, then the Worker will be able to Discover, i.e. see the HIT in their search result, but will not be able to Preview or Accept the HIT. ActionsGuarded should not be used in combination with the <code>RequiredToPreview</code> field.</p>
    pub fn actions_guarded(&self) -> ::std::option::Option<&crate::types::HitAccessActions> {
        self.actions_guarded.as_ref()
    }
}
impl QualificationRequirement {
    /// Creates a new builder-style object to manufacture [`QualificationRequirement`](crate::types::QualificationRequirement).
    pub fn builder() -> crate::types::builders::QualificationRequirementBuilder {
        crate::types::builders::QualificationRequirementBuilder::default()
    }
}

/// A builder for [`QualificationRequirement`](crate::types::QualificationRequirement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QualificationRequirementBuilder {
    pub(crate) qualification_type_id: ::std::option::Option<::std::string::String>,
    pub(crate) comparator: ::std::option::Option<crate::types::Comparator>,
    pub(crate) integer_values: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) locale_values: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>,
    pub(crate) required_to_preview: ::std::option::Option<bool>,
    pub(crate) actions_guarded: ::std::option::Option<crate::types::HitAccessActions>,
}
impl QualificationRequirementBuilder {
    /// <p>The ID of the Qualification type for the requirement.</p>
    /// This field is required.
    pub fn qualification_type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.qualification_type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Qualification type for the requirement.</p>
    pub fn set_qualification_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.qualification_type_id = input;
        self
    }
    /// <p>The ID of the Qualification type for the requirement.</p>
    pub fn get_qualification_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.qualification_type_id
    }
    /// <p>The kind of comparison to make against a Qualification's value. You can compare a Qualification's value to an IntegerValue to see if it is LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, EqualTo, or NotEqualTo the IntegerValue. You can compare it to a LocaleValue to see if it is EqualTo, or NotEqualTo the LocaleValue. You can check to see if the value is In or NotIn a set of IntegerValue or LocaleValue values. Lastly, a Qualification requirement can also test if a Qualification Exists or DoesNotExist in the user's profile, regardless of its value.</p>
    /// This field is required.
    pub fn comparator(mut self, input: crate::types::Comparator) -> Self {
        self.comparator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The kind of comparison to make against a Qualification's value. You can compare a Qualification's value to an IntegerValue to see if it is LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, EqualTo, or NotEqualTo the IntegerValue. You can compare it to a LocaleValue to see if it is EqualTo, or NotEqualTo the LocaleValue. You can check to see if the value is In or NotIn a set of IntegerValue or LocaleValue values. Lastly, a Qualification requirement can also test if a Qualification Exists or DoesNotExist in the user's profile, regardless of its value.</p>
    pub fn set_comparator(mut self, input: ::std::option::Option<crate::types::Comparator>) -> Self {
        self.comparator = input;
        self
    }
    /// <p>The kind of comparison to make against a Qualification's value. You can compare a Qualification's value to an IntegerValue to see if it is LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, EqualTo, or NotEqualTo the IntegerValue. You can compare it to a LocaleValue to see if it is EqualTo, or NotEqualTo the LocaleValue. You can check to see if the value is In or NotIn a set of IntegerValue or LocaleValue values. Lastly, a Qualification requirement can also test if a Qualification Exists or DoesNotExist in the user's profile, regardless of its value.</p>
    pub fn get_comparator(&self) -> &::std::option::Option<crate::types::Comparator> {
        &self.comparator
    }
    /// Appends an item to `integer_values`.
    ///
    /// To override the contents of this collection use [`set_integer_values`](Self::set_integer_values).
    ///
    /// <p>The integer value to compare against the Qualification's value. IntegerValue must not be present if Comparator is Exists or DoesNotExist. IntegerValue can only be used if the Qualification type has an integer value; it cannot be used with the Worker_Locale QualificationType ID. When performing a set comparison by using the In or the NotIn comparator, you can use up to 15 IntegerValue elements in a QualificationRequirement data structure.</p>
    pub fn integer_values(mut self, input: i32) -> Self {
        let mut v = self.integer_values.unwrap_or_default();
        v.push(input);
        self.integer_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The integer value to compare against the Qualification's value. IntegerValue must not be present if Comparator is Exists or DoesNotExist. IntegerValue can only be used if the Qualification type has an integer value; it cannot be used with the Worker_Locale QualificationType ID. When performing a set comparison by using the In or the NotIn comparator, you can use up to 15 IntegerValue elements in a QualificationRequirement data structure.</p>
    pub fn set_integer_values(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.integer_values = input;
        self
    }
    /// <p>The integer value to compare against the Qualification's value. IntegerValue must not be present if Comparator is Exists or DoesNotExist. IntegerValue can only be used if the Qualification type has an integer value; it cannot be used with the Worker_Locale QualificationType ID. When performing a set comparison by using the In or the NotIn comparator, you can use up to 15 IntegerValue elements in a QualificationRequirement data structure.</p>
    pub fn get_integer_values(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.integer_values
    }
    /// Appends an item to `locale_values`.
    ///
    /// To override the contents of this collection use [`set_locale_values`](Self::set_locale_values).
    ///
    /// <p>The locale value to compare against the Qualification's value. The local value must be a valid ISO 3166 country code or supports ISO 3166-2 subdivisions. LocaleValue can only be used with a Worker_Locale QualificationType ID. LocaleValue can only be used with the EqualTo, NotEqualTo, In, and NotIn comparators. You must only use a single LocaleValue element when using the EqualTo or NotEqualTo comparators. When performing a set comparison by using the In or the NotIn comparator, you can use up to 30 LocaleValue elements in a QualificationRequirement data structure.</p>
    pub fn locale_values(mut self, input: crate::types::Locale) -> Self {
        let mut v = self.locale_values.unwrap_or_default();
        v.push(input);
        self.locale_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The locale value to compare against the Qualification's value. The local value must be a valid ISO 3166 country code or supports ISO 3166-2 subdivisions. LocaleValue can only be used with a Worker_Locale QualificationType ID. LocaleValue can only be used with the EqualTo, NotEqualTo, In, and NotIn comparators. You must only use a single LocaleValue element when using the EqualTo or NotEqualTo comparators. When performing a set comparison by using the In or the NotIn comparator, you can use up to 30 LocaleValue elements in a QualificationRequirement data structure.</p>
    pub fn set_locale_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>) -> Self {
        self.locale_values = input;
        self
    }
    /// <p>The locale value to compare against the Qualification's value. The local value must be a valid ISO 3166 country code or supports ISO 3166-2 subdivisions. LocaleValue can only be used with a Worker_Locale QualificationType ID. LocaleValue can only be used with the EqualTo, NotEqualTo, In, and NotIn comparators. You must only use a single LocaleValue element when using the EqualTo or NotEqualTo comparators. When performing a set comparison by using the In or the NotIn comparator, you can use up to 30 LocaleValue elements in a QualificationRequirement data structure.</p>
    pub fn get_locale_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Locale>> {
        &self.locale_values
    }
    /// <p>DEPRECATED: Use the <code>ActionsGuarded</code> field instead. If RequiredToPreview is true, the question data for the HIT will not be shown when a Worker whose Qualifications do not meet this requirement tries to preview the HIT. That is, a Worker's Qualifications must meet all of the requirements for which RequiredToPreview is true in order to preview the HIT. If a Worker meets all of the requirements where RequiredToPreview is true (or if there are no such requirements), but does not meet all of the requirements for the HIT, the Worker will be allowed to preview the HIT's question data, but will not be allowed to accept and complete the HIT. The default is false. This should not be used in combination with the <code>ActionsGuarded</code> field.</p>
    #[deprecated]
    pub fn required_to_preview(mut self, input: bool) -> Self {
        self.required_to_preview = ::std::option::Option::Some(input);
        self
    }
    /// <p>DEPRECATED: Use the <code>ActionsGuarded</code> field instead. If RequiredToPreview is true, the question data for the HIT will not be shown when a Worker whose Qualifications do not meet this requirement tries to preview the HIT. That is, a Worker's Qualifications must meet all of the requirements for which RequiredToPreview is true in order to preview the HIT. If a Worker meets all of the requirements where RequiredToPreview is true (or if there are no such requirements), but does not meet all of the requirements for the HIT, the Worker will be allowed to preview the HIT's question data, but will not be allowed to accept and complete the HIT. The default is false. This should not be used in combination with the <code>ActionsGuarded</code> field.</p>
    #[deprecated]
    pub fn set_required_to_preview(mut self, input: ::std::option::Option<bool>) -> Self {
        self.required_to_preview = input;
        self
    }
    /// <p>DEPRECATED: Use the <code>ActionsGuarded</code> field instead. If RequiredToPreview is true, the question data for the HIT will not be shown when a Worker whose Qualifications do not meet this requirement tries to preview the HIT. That is, a Worker's Qualifications must meet all of the requirements for which RequiredToPreview is true in order to preview the HIT. If a Worker meets all of the requirements where RequiredToPreview is true (or if there are no such requirements), but does not meet all of the requirements for the HIT, the Worker will be allowed to preview the HIT's question data, but will not be allowed to accept and complete the HIT. The default is false. This should not be used in combination with the <code>ActionsGuarded</code> field.</p>
    #[deprecated]
    pub fn get_required_to_preview(&self) -> &::std::option::Option<bool> {
        &self.required_to_preview
    }
    /// <p>Setting this attribute prevents Workers whose Qualifications do not meet this QualificationRequirement from taking the specified action. Valid arguments include "Accept" (Worker cannot accept the HIT, but can preview the HIT and see it in their search results), "PreviewAndAccept" (Worker cannot accept or preview the HIT, but can see the HIT in their search results), and "DiscoverPreviewAndAccept" (Worker cannot accept, preview, or see the HIT in their search results). It's possible for you to create a HIT with multiple QualificationRequirements (which can have different values for the ActionGuarded attribute). In this case, the Worker is only permitted to perform an action when they have met all QualificationRequirements guarding the action. The actions in the order of least restrictive to most restrictive are Discover, Preview and Accept. For example, if a Worker meets all QualificationRequirements that are set to DiscoverPreviewAndAccept, but do not meet all requirements that are set with PreviewAndAccept, then the Worker will be able to Discover, i.e. see the HIT in their search result, but will not be able to Preview or Accept the HIT. ActionsGuarded should not be used in combination with the <code>RequiredToPreview</code> field.</p>
    pub fn actions_guarded(mut self, input: crate::types::HitAccessActions) -> Self {
        self.actions_guarded = ::std::option::Option::Some(input);
        self
    }
    /// <p>Setting this attribute prevents Workers whose Qualifications do not meet this QualificationRequirement from taking the specified action. Valid arguments include "Accept" (Worker cannot accept the HIT, but can preview the HIT and see it in their search results), "PreviewAndAccept" (Worker cannot accept or preview the HIT, but can see the HIT in their search results), and "DiscoverPreviewAndAccept" (Worker cannot accept, preview, or see the HIT in their search results). It's possible for you to create a HIT with multiple QualificationRequirements (which can have different values for the ActionGuarded attribute). In this case, the Worker is only permitted to perform an action when they have met all QualificationRequirements guarding the action. The actions in the order of least restrictive to most restrictive are Discover, Preview and Accept. For example, if a Worker meets all QualificationRequirements that are set to DiscoverPreviewAndAccept, but do not meet all requirements that are set with PreviewAndAccept, then the Worker will be able to Discover, i.e. see the HIT in their search result, but will not be able to Preview or Accept the HIT. ActionsGuarded should not be used in combination with the <code>RequiredToPreview</code> field.</p>
    pub fn set_actions_guarded(mut self, input: ::std::option::Option<crate::types::HitAccessActions>) -> Self {
        self.actions_guarded = input;
        self
    }
    /// <p>Setting this attribute prevents Workers whose Qualifications do not meet this QualificationRequirement from taking the specified action. Valid arguments include "Accept" (Worker cannot accept the HIT, but can preview the HIT and see it in their search results), "PreviewAndAccept" (Worker cannot accept or preview the HIT, but can see the HIT in their search results), and "DiscoverPreviewAndAccept" (Worker cannot accept, preview, or see the HIT in their search results). It's possible for you to create a HIT with multiple QualificationRequirements (which can have different values for the ActionGuarded attribute). In this case, the Worker is only permitted to perform an action when they have met all QualificationRequirements guarding the action. The actions in the order of least restrictive to most restrictive are Discover, Preview and Accept. For example, if a Worker meets all QualificationRequirements that are set to DiscoverPreviewAndAccept, but do not meet all requirements that are set with PreviewAndAccept, then the Worker will be able to Discover, i.e. see the HIT in their search result, but will not be able to Preview or Accept the HIT. ActionsGuarded should not be used in combination with the <code>RequiredToPreview</code> field.</p>
    pub fn get_actions_guarded(&self) -> &::std::option::Option<crate::types::HitAccessActions> {
        &self.actions_guarded
    }
    /// Consumes the builder and constructs a [`QualificationRequirement`](crate::types::QualificationRequirement).
    /// This method will fail if any of the following fields are not set:
    /// - [`qualification_type_id`](crate::types::builders::QualificationRequirementBuilder::qualification_type_id)
    /// - [`comparator`](crate::types::builders::QualificationRequirementBuilder::comparator)
    pub fn build(self) -> ::std::result::Result<crate::types::QualificationRequirement, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QualificationRequirement {
            qualification_type_id: self.qualification_type_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "qualification_type_id",
                    "qualification_type_id was not specified but it is required when building QualificationRequirement",
                )
            })?,
            comparator: self.comparator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparator",
                    "comparator was not specified but it is required when building QualificationRequirement",
                )
            })?,
            integer_values: self.integer_values,
            locale_values: self.locale_values,
            required_to_preview: self.required_to_preview,
            actions_guarded: self.actions_guarded,
        })
    }
}

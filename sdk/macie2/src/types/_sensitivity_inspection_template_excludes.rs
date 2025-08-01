// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies managed data identifiers to exclude (not use) when performing automated sensitive data discovery. For information about the managed data identifiers that Amazon Macie currently provides, see <a href="https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html">Using managed data identifiers</a> in the <i>Amazon Macie User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SensitivityInspectionTemplateExcludes {
    /// <p>An array of unique identifiers, one for each managed data identifier to exclude. To retrieve a list of valid values, use the ListManagedDataIdentifiers operation.</p>
    pub managed_data_identifier_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SensitivityInspectionTemplateExcludes {
    /// <p>An array of unique identifiers, one for each managed data identifier to exclude. To retrieve a list of valid values, use the ListManagedDataIdentifiers operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.managed_data_identifier_ids.is_none()`.
    pub fn managed_data_identifier_ids(&self) -> &[::std::string::String] {
        self.managed_data_identifier_ids.as_deref().unwrap_or_default()
    }
}
impl SensitivityInspectionTemplateExcludes {
    /// Creates a new builder-style object to manufacture [`SensitivityInspectionTemplateExcludes`](crate::types::SensitivityInspectionTemplateExcludes).
    pub fn builder() -> crate::types::builders::SensitivityInspectionTemplateExcludesBuilder {
        crate::types::builders::SensitivityInspectionTemplateExcludesBuilder::default()
    }
}

/// A builder for [`SensitivityInspectionTemplateExcludes`](crate::types::SensitivityInspectionTemplateExcludes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SensitivityInspectionTemplateExcludesBuilder {
    pub(crate) managed_data_identifier_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SensitivityInspectionTemplateExcludesBuilder {
    /// Appends an item to `managed_data_identifier_ids`.
    ///
    /// To override the contents of this collection use [`set_managed_data_identifier_ids`](Self::set_managed_data_identifier_ids).
    ///
    /// <p>An array of unique identifiers, one for each managed data identifier to exclude. To retrieve a list of valid values, use the ListManagedDataIdentifiers operation.</p>
    pub fn managed_data_identifier_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.managed_data_identifier_ids.unwrap_or_default();
        v.push(input.into());
        self.managed_data_identifier_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of unique identifiers, one for each managed data identifier to exclude. To retrieve a list of valid values, use the ListManagedDataIdentifiers operation.</p>
    pub fn set_managed_data_identifier_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.managed_data_identifier_ids = input;
        self
    }
    /// <p>An array of unique identifiers, one for each managed data identifier to exclude. To retrieve a list of valid values, use the ListManagedDataIdentifiers operation.</p>
    pub fn get_managed_data_identifier_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.managed_data_identifier_ids
    }
    /// Consumes the builder and constructs a [`SensitivityInspectionTemplateExcludes`](crate::types::SensitivityInspectionTemplateExcludes).
    pub fn build(self) -> crate::types::SensitivityInspectionTemplateExcludes {
        crate::types::SensitivityInspectionTemplateExcludes {
            managed_data_identifier_ids: self.managed_data_identifier_ids,
        }
    }
}

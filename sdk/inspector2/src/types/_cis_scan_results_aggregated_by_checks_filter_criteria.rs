// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The scan results aggregated by checks filter criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CisScanResultsAggregatedByChecksFilterCriteria {
    /// <p>The criteria's account ID filters.</p>
    pub account_id_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    /// <p>The criteria's check ID filters.</p>
    pub check_id_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    /// <p>The criteria's title filters.</p>
    pub title_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    /// <p>The criteria's platform filters.</p>
    pub platform_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    /// <p>The criteria's failed resources filters.</p>
    pub failed_resources_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisNumberFilter>>,
    /// <p>The criteria's security level filters.</p>
    pub security_level_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisSecurityLevelFilter>>,
}
impl CisScanResultsAggregatedByChecksFilterCriteria {
    /// <p>The criteria's account ID filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_id_filters.is_none()`.
    pub fn account_id_filters(&self) -> &[crate::types::CisStringFilter] {
        self.account_id_filters.as_deref().unwrap_or_default()
    }
    /// <p>The criteria's check ID filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.check_id_filters.is_none()`.
    pub fn check_id_filters(&self) -> &[crate::types::CisStringFilter] {
        self.check_id_filters.as_deref().unwrap_or_default()
    }
    /// <p>The criteria's title filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.title_filters.is_none()`.
    pub fn title_filters(&self) -> &[crate::types::CisStringFilter] {
        self.title_filters.as_deref().unwrap_or_default()
    }
    /// <p>The criteria's platform filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.platform_filters.is_none()`.
    pub fn platform_filters(&self) -> &[crate::types::CisStringFilter] {
        self.platform_filters.as_deref().unwrap_or_default()
    }
    /// <p>The criteria's failed resources filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_resources_filters.is_none()`.
    pub fn failed_resources_filters(&self) -> &[crate::types::CisNumberFilter] {
        self.failed_resources_filters.as_deref().unwrap_or_default()
    }
    /// <p>The criteria's security level filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_level_filters.is_none()`.
    pub fn security_level_filters(&self) -> &[crate::types::CisSecurityLevelFilter] {
        self.security_level_filters.as_deref().unwrap_or_default()
    }
}
impl CisScanResultsAggregatedByChecksFilterCriteria {
    /// Creates a new builder-style object to manufacture [`CisScanResultsAggregatedByChecksFilterCriteria`](crate::types::CisScanResultsAggregatedByChecksFilterCriteria).
    pub fn builder() -> crate::types::builders::CisScanResultsAggregatedByChecksFilterCriteriaBuilder {
        crate::types::builders::CisScanResultsAggregatedByChecksFilterCriteriaBuilder::default()
    }
}

/// A builder for [`CisScanResultsAggregatedByChecksFilterCriteria`](crate::types::CisScanResultsAggregatedByChecksFilterCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CisScanResultsAggregatedByChecksFilterCriteriaBuilder {
    pub(crate) account_id_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    pub(crate) check_id_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    pub(crate) title_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    pub(crate) platform_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>,
    pub(crate) failed_resources_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisNumberFilter>>,
    pub(crate) security_level_filters: ::std::option::Option<::std::vec::Vec<crate::types::CisSecurityLevelFilter>>,
}
impl CisScanResultsAggregatedByChecksFilterCriteriaBuilder {
    /// Appends an item to `account_id_filters`.
    ///
    /// To override the contents of this collection use [`set_account_id_filters`](Self::set_account_id_filters).
    ///
    /// <p>The criteria's account ID filters.</p>
    pub fn account_id_filters(mut self, input: crate::types::CisStringFilter) -> Self {
        let mut v = self.account_id_filters.unwrap_or_default();
        v.push(input);
        self.account_id_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's account ID filters.</p>
    pub fn set_account_id_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>) -> Self {
        self.account_id_filters = input;
        self
    }
    /// <p>The criteria's account ID filters.</p>
    pub fn get_account_id_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>> {
        &self.account_id_filters
    }
    /// Appends an item to `check_id_filters`.
    ///
    /// To override the contents of this collection use [`set_check_id_filters`](Self::set_check_id_filters).
    ///
    /// <p>The criteria's check ID filters.</p>
    pub fn check_id_filters(mut self, input: crate::types::CisStringFilter) -> Self {
        let mut v = self.check_id_filters.unwrap_or_default();
        v.push(input);
        self.check_id_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's check ID filters.</p>
    pub fn set_check_id_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>) -> Self {
        self.check_id_filters = input;
        self
    }
    /// <p>The criteria's check ID filters.</p>
    pub fn get_check_id_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>> {
        &self.check_id_filters
    }
    /// Appends an item to `title_filters`.
    ///
    /// To override the contents of this collection use [`set_title_filters`](Self::set_title_filters).
    ///
    /// <p>The criteria's title filters.</p>
    pub fn title_filters(mut self, input: crate::types::CisStringFilter) -> Self {
        let mut v = self.title_filters.unwrap_or_default();
        v.push(input);
        self.title_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's title filters.</p>
    pub fn set_title_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>) -> Self {
        self.title_filters = input;
        self
    }
    /// <p>The criteria's title filters.</p>
    pub fn get_title_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>> {
        &self.title_filters
    }
    /// Appends an item to `platform_filters`.
    ///
    /// To override the contents of this collection use [`set_platform_filters`](Self::set_platform_filters).
    ///
    /// <p>The criteria's platform filters.</p>
    pub fn platform_filters(mut self, input: crate::types::CisStringFilter) -> Self {
        let mut v = self.platform_filters.unwrap_or_default();
        v.push(input);
        self.platform_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's platform filters.</p>
    pub fn set_platform_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>>) -> Self {
        self.platform_filters = input;
        self
    }
    /// <p>The criteria's platform filters.</p>
    pub fn get_platform_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisStringFilter>> {
        &self.platform_filters
    }
    /// Appends an item to `failed_resources_filters`.
    ///
    /// To override the contents of this collection use [`set_failed_resources_filters`](Self::set_failed_resources_filters).
    ///
    /// <p>The criteria's failed resources filters.</p>
    pub fn failed_resources_filters(mut self, input: crate::types::CisNumberFilter) -> Self {
        let mut v = self.failed_resources_filters.unwrap_or_default();
        v.push(input);
        self.failed_resources_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's failed resources filters.</p>
    pub fn set_failed_resources_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisNumberFilter>>) -> Self {
        self.failed_resources_filters = input;
        self
    }
    /// <p>The criteria's failed resources filters.</p>
    pub fn get_failed_resources_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisNumberFilter>> {
        &self.failed_resources_filters
    }
    /// Appends an item to `security_level_filters`.
    ///
    /// To override the contents of this collection use [`set_security_level_filters`](Self::set_security_level_filters).
    ///
    /// <p>The criteria's security level filters.</p>
    pub fn security_level_filters(mut self, input: crate::types::CisSecurityLevelFilter) -> Self {
        let mut v = self.security_level_filters.unwrap_or_default();
        v.push(input);
        self.security_level_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The criteria's security level filters.</p>
    pub fn set_security_level_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CisSecurityLevelFilter>>) -> Self {
        self.security_level_filters = input;
        self
    }
    /// <p>The criteria's security level filters.</p>
    pub fn get_security_level_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CisSecurityLevelFilter>> {
        &self.security_level_filters
    }
    /// Consumes the builder and constructs a [`CisScanResultsAggregatedByChecksFilterCriteria`](crate::types::CisScanResultsAggregatedByChecksFilterCriteria).
    pub fn build(self) -> crate::types::CisScanResultsAggregatedByChecksFilterCriteria {
        crate::types::CisScanResultsAggregatedByChecksFilterCriteria {
            account_id_filters: self.account_id_filters,
            check_id_filters: self.check_id_filters,
            title_filters: self.title_filters,
            platform_filters: self.platform_filters,
            failed_resources_filters: self.failed_resources_filters,
            security_level_filters: self.security_level_filters,
        }
    }
}

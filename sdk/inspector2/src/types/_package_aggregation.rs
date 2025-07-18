// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details that define an aggregation based on operating system package type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PackageAggregation {
    /// <p>The names of packages to aggregate findings on.</p>
    pub package_names: ::std::option::Option<::std::vec::Vec<crate::types::StringFilter>>,
    /// <p>The order to sort results by.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>The value to sort results by.</p>
    pub sort_by: ::std::option::Option<crate::types::PackageSortBy>,
}
impl PackageAggregation {
    /// <p>The names of packages to aggregate findings on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.package_names.is_none()`.
    pub fn package_names(&self) -> &[crate::types::StringFilter] {
        self.package_names.as_deref().unwrap_or_default()
    }
    /// <p>The order to sort results by.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>The value to sort results by.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::PackageSortBy> {
        self.sort_by.as_ref()
    }
}
impl PackageAggregation {
    /// Creates a new builder-style object to manufacture [`PackageAggregation`](crate::types::PackageAggregation).
    pub fn builder() -> crate::types::builders::PackageAggregationBuilder {
        crate::types::builders::PackageAggregationBuilder::default()
    }
}

/// A builder for [`PackageAggregation`](crate::types::PackageAggregation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PackageAggregationBuilder {
    pub(crate) package_names: ::std::option::Option<::std::vec::Vec<crate::types::StringFilter>>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) sort_by: ::std::option::Option<crate::types::PackageSortBy>,
}
impl PackageAggregationBuilder {
    /// Appends an item to `package_names`.
    ///
    /// To override the contents of this collection use [`set_package_names`](Self::set_package_names).
    ///
    /// <p>The names of packages to aggregate findings on.</p>
    pub fn package_names(mut self, input: crate::types::StringFilter) -> Self {
        let mut v = self.package_names.unwrap_or_default();
        v.push(input);
        self.package_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of packages to aggregate findings on.</p>
    pub fn set_package_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StringFilter>>) -> Self {
        self.package_names = input;
        self
    }
    /// <p>The names of packages to aggregate findings on.</p>
    pub fn get_package_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StringFilter>> {
        &self.package_names
    }
    /// <p>The order to sort results by.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order to sort results by.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The order to sort results by.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>The value to sort results by.</p>
    pub fn sort_by(mut self, input: crate::types::PackageSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value to sort results by.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::PackageSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The value to sort results by.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::PackageSortBy> {
        &self.sort_by
    }
    /// Consumes the builder and constructs a [`PackageAggregation`](crate::types::PackageAggregation).
    pub fn build(self) -> crate::types::PackageAggregation {
        crate::types::PackageAggregation {
            package_names: self.package_names,
            sort_order: self.sort_order,
            sort_by: self.sort_by,
        }
    }
}

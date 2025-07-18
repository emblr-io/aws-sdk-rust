// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApproximateUsageRecordsInput {
    /// <p>How granular you want the data to be. You can enable data at hourly or daily granularity.</p>
    pub granularity: ::std::option::Option<crate::types::Granularity>,
    /// <p>The service metadata for the service or services you want to query. If not specified, all elements are returned.</p>
    pub services: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The service to evaluate for the usage records. You can choose resource-level data at daily granularity, or hourly granularity with or without resource-level data.</p>
    pub approximation_dimension: ::std::option::Option<crate::types::ApproximationDimension>,
}
impl GetApproximateUsageRecordsInput {
    /// <p>How granular you want the data to be. You can enable data at hourly or daily granularity.</p>
    pub fn granularity(&self) -> ::std::option::Option<&crate::types::Granularity> {
        self.granularity.as_ref()
    }
    /// <p>The service metadata for the service or services you want to query. If not specified, all elements are returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.services.is_none()`.
    pub fn services(&self) -> &[::std::string::String] {
        self.services.as_deref().unwrap_or_default()
    }
    /// <p>The service to evaluate for the usage records. You can choose resource-level data at daily granularity, or hourly granularity with or without resource-level data.</p>
    pub fn approximation_dimension(&self) -> ::std::option::Option<&crate::types::ApproximationDimension> {
        self.approximation_dimension.as_ref()
    }
}
impl GetApproximateUsageRecordsInput {
    /// Creates a new builder-style object to manufacture [`GetApproximateUsageRecordsInput`](crate::operation::get_approximate_usage_records::GetApproximateUsageRecordsInput).
    pub fn builder() -> crate::operation::get_approximate_usage_records::builders::GetApproximateUsageRecordsInputBuilder {
        crate::operation::get_approximate_usage_records::builders::GetApproximateUsageRecordsInputBuilder::default()
    }
}

/// A builder for [`GetApproximateUsageRecordsInput`](crate::operation::get_approximate_usage_records::GetApproximateUsageRecordsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApproximateUsageRecordsInputBuilder {
    pub(crate) granularity: ::std::option::Option<crate::types::Granularity>,
    pub(crate) services: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) approximation_dimension: ::std::option::Option<crate::types::ApproximationDimension>,
}
impl GetApproximateUsageRecordsInputBuilder {
    /// <p>How granular you want the data to be. You can enable data at hourly or daily granularity.</p>
    /// This field is required.
    pub fn granularity(mut self, input: crate::types::Granularity) -> Self {
        self.granularity = ::std::option::Option::Some(input);
        self
    }
    /// <p>How granular you want the data to be. You can enable data at hourly or daily granularity.</p>
    pub fn set_granularity(mut self, input: ::std::option::Option<crate::types::Granularity>) -> Self {
        self.granularity = input;
        self
    }
    /// <p>How granular you want the data to be. You can enable data at hourly or daily granularity.</p>
    pub fn get_granularity(&self) -> &::std::option::Option<crate::types::Granularity> {
        &self.granularity
    }
    /// Appends an item to `services`.
    ///
    /// To override the contents of this collection use [`set_services`](Self::set_services).
    ///
    /// <p>The service metadata for the service or services you want to query. If not specified, all elements are returned.</p>
    pub fn services(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.services.unwrap_or_default();
        v.push(input.into());
        self.services = ::std::option::Option::Some(v);
        self
    }
    /// <p>The service metadata for the service or services you want to query. If not specified, all elements are returned.</p>
    pub fn set_services(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.services = input;
        self
    }
    /// <p>The service metadata for the service or services you want to query. If not specified, all elements are returned.</p>
    pub fn get_services(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.services
    }
    /// <p>The service to evaluate for the usage records. You can choose resource-level data at daily granularity, or hourly granularity with or without resource-level data.</p>
    /// This field is required.
    pub fn approximation_dimension(mut self, input: crate::types::ApproximationDimension) -> Self {
        self.approximation_dimension = ::std::option::Option::Some(input);
        self
    }
    /// <p>The service to evaluate for the usage records. You can choose resource-level data at daily granularity, or hourly granularity with or without resource-level data.</p>
    pub fn set_approximation_dimension(mut self, input: ::std::option::Option<crate::types::ApproximationDimension>) -> Self {
        self.approximation_dimension = input;
        self
    }
    /// <p>The service to evaluate for the usage records. You can choose resource-level data at daily granularity, or hourly granularity with or without resource-level data.</p>
    pub fn get_approximation_dimension(&self) -> &::std::option::Option<crate::types::ApproximationDimension> {
        &self.approximation_dimension
    }
    /// Consumes the builder and constructs a [`GetApproximateUsageRecordsInput`](crate::operation::get_approximate_usage_records::GetApproximateUsageRecordsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_approximate_usage_records::GetApproximateUsageRecordsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_approximate_usage_records::GetApproximateUsageRecordsInput {
            granularity: self.granularity,
            services: self.services,
            approximation_dimension: self.approximation_dimension,
        })
    }
}

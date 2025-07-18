// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Limits that are applicable for given storage type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageTypeLimit {
    /// <p>Name of storage limits that are applicable for given storage type. If <code> <code>StorageType</code> </code> is ebs, following storage options are applicable</p>
    /// <ol>
    /// <li>MinimumVolumeSize</li> Minimum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumVolumeSize</li> Maximum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumIops</li> Maximum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumIops</li> Minimum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumThroughput</li> Maximum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumThroughput</li> Minimum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// </ol>
    /// <p></p>
    pub limit_name: ::std::option::Option<::std::string::String>,
    /// <p>Values for the <code> <code>StorageTypeLimit$LimitName</code> </code> .</p>
    pub limit_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl StorageTypeLimit {
    /// <p>Name of storage limits that are applicable for given storage type. If <code> <code>StorageType</code> </code> is ebs, following storage options are applicable</p>
    /// <ol>
    /// <li>MinimumVolumeSize</li> Minimum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumVolumeSize</li> Maximum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumIops</li> Maximum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumIops</li> Minimum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumThroughput</li> Maximum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumThroughput</li> Minimum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// </ol>
    /// <p></p>
    pub fn limit_name(&self) -> ::std::option::Option<&str> {
        self.limit_name.as_deref()
    }
    /// <p>Values for the <code> <code>StorageTypeLimit$LimitName</code> </code> .</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.limit_values.is_none()`.
    pub fn limit_values(&self) -> &[::std::string::String] {
        self.limit_values.as_deref().unwrap_or_default()
    }
}
impl StorageTypeLimit {
    /// Creates a new builder-style object to manufacture [`StorageTypeLimit`](crate::types::StorageTypeLimit).
    pub fn builder() -> crate::types::builders::StorageTypeLimitBuilder {
        crate::types::builders::StorageTypeLimitBuilder::default()
    }
}

/// A builder for [`StorageTypeLimit`](crate::types::StorageTypeLimit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageTypeLimitBuilder {
    pub(crate) limit_name: ::std::option::Option<::std::string::String>,
    pub(crate) limit_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl StorageTypeLimitBuilder {
    /// <p>Name of storage limits that are applicable for given storage type. If <code> <code>StorageType</code> </code> is ebs, following storage options are applicable</p>
    /// <ol>
    /// <li>MinimumVolumeSize</li> Minimum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumVolumeSize</li> Maximum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumIops</li> Maximum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumIops</li> Minimum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumThroughput</li> Maximum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumThroughput</li> Minimum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// </ol>
    /// <p></p>
    pub fn limit_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.limit_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of storage limits that are applicable for given storage type. If <code> <code>StorageType</code> </code> is ebs, following storage options are applicable</p>
    /// <ol>
    /// <li>MinimumVolumeSize</li> Minimum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumVolumeSize</li> Maximum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumIops</li> Maximum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumIops</li> Minimum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumThroughput</li> Maximum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumThroughput</li> Minimum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// </ol>
    /// <p></p>
    pub fn set_limit_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.limit_name = input;
        self
    }
    /// <p>Name of storage limits that are applicable for given storage type. If <code> <code>StorageType</code> </code> is ebs, following storage options are applicable</p>
    /// <ol>
    /// <li>MinimumVolumeSize</li> Minimum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumVolumeSize</li> Maximum amount of volume size that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumIops</li> Maximum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumIops</li> Minimum amount of Iops that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MaximumThroughput</li> Maximum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// <li>MinimumThroughput</li> Minimum amount of Throughput that is applicable for given storage type.It can be empty if it is not applicable.
    /// </ol>
    /// <p></p>
    pub fn get_limit_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.limit_name
    }
    /// Appends an item to `limit_values`.
    ///
    /// To override the contents of this collection use [`set_limit_values`](Self::set_limit_values).
    ///
    /// <p>Values for the <code> <code>StorageTypeLimit$LimitName</code> </code> .</p>
    pub fn limit_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.limit_values.unwrap_or_default();
        v.push(input.into());
        self.limit_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Values for the <code> <code>StorageTypeLimit$LimitName</code> </code> .</p>
    pub fn set_limit_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.limit_values = input;
        self
    }
    /// <p>Values for the <code> <code>StorageTypeLimit$LimitName</code> </code> .</p>
    pub fn get_limit_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.limit_values
    }
    /// Consumes the builder and constructs a [`StorageTypeLimit`](crate::types::StorageTypeLimit).
    pub fn build(self) -> crate::types::StorageTypeLimit {
        crate::types::StorageTypeLimit {
            limit_name: self.limit_name,
            limit_values: self.limit_values,
        }
    }
}

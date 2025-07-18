// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The estimated monthly savings after you adjust the configurations of your instances running on the inferred workload types to the recommended configurations. If the <code>inferredWorkloadTypes</code> list contains multiple entries, then the savings are the sum of the monthly savings from instances that run the exact combination of the inferred workload types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferredWorkloadSaving {
    /// <p>The applications that might be running on the instance as inferred by Compute Optimizer.</p>
    /// <p>Compute Optimizer can infer if one of the following applications might be running on the instance:</p>
    /// <ul>
    /// <li>
    /// <p><code>AmazonEmr</code> - Infers that Amazon EMR might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheCassandra</code> - Infers that Apache Cassandra might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheHadoop</code> - Infers that Apache Hadoop might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Memcached</code> - Infers that Memcached might be running on the instance.</p></li>
    /// <li>
    /// <p><code>NGINX</code> - Infers that NGINX might be running on the instance.</p></li>
    /// <li>
    /// <p><code>PostgreSql</code> - Infers that PostgreSQL might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Redis</code> - Infers that Redis might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Kafka</code> - Infers that Kafka might be running on the instance.</p></li>
    /// <li>
    /// <p><code>SQLServer</code> - Infers that SQLServer might be running on the instance.</p></li>
    /// </ul>
    pub inferred_workload_types: ::std::option::Option<::std::vec::Vec<crate::types::InferredWorkloadType>>,
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing.</p>
    pub estimated_monthly_savings: ::std::option::Option<crate::types::EstimatedMonthlySavings>,
}
impl InferredWorkloadSaving {
    /// <p>The applications that might be running on the instance as inferred by Compute Optimizer.</p>
    /// <p>Compute Optimizer can infer if one of the following applications might be running on the instance:</p>
    /// <ul>
    /// <li>
    /// <p><code>AmazonEmr</code> - Infers that Amazon EMR might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheCassandra</code> - Infers that Apache Cassandra might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheHadoop</code> - Infers that Apache Hadoop might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Memcached</code> - Infers that Memcached might be running on the instance.</p></li>
    /// <li>
    /// <p><code>NGINX</code> - Infers that NGINX might be running on the instance.</p></li>
    /// <li>
    /// <p><code>PostgreSql</code> - Infers that PostgreSQL might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Redis</code> - Infers that Redis might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Kafka</code> - Infers that Kafka might be running on the instance.</p></li>
    /// <li>
    /// <p><code>SQLServer</code> - Infers that SQLServer might be running on the instance.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inferred_workload_types.is_none()`.
    pub fn inferred_workload_types(&self) -> &[crate::types::InferredWorkloadType] {
        self.inferred_workload_types.as_deref().unwrap_or_default()
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing.</p>
    pub fn estimated_monthly_savings(&self) -> ::std::option::Option<&crate::types::EstimatedMonthlySavings> {
        self.estimated_monthly_savings.as_ref()
    }
}
impl InferredWorkloadSaving {
    /// Creates a new builder-style object to manufacture [`InferredWorkloadSaving`](crate::types::InferredWorkloadSaving).
    pub fn builder() -> crate::types::builders::InferredWorkloadSavingBuilder {
        crate::types::builders::InferredWorkloadSavingBuilder::default()
    }
}

/// A builder for [`InferredWorkloadSaving`](crate::types::InferredWorkloadSaving).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferredWorkloadSavingBuilder {
    pub(crate) inferred_workload_types: ::std::option::Option<::std::vec::Vec<crate::types::InferredWorkloadType>>,
    pub(crate) estimated_monthly_savings: ::std::option::Option<crate::types::EstimatedMonthlySavings>,
}
impl InferredWorkloadSavingBuilder {
    /// Appends an item to `inferred_workload_types`.
    ///
    /// To override the contents of this collection use [`set_inferred_workload_types`](Self::set_inferred_workload_types).
    ///
    /// <p>The applications that might be running on the instance as inferred by Compute Optimizer.</p>
    /// <p>Compute Optimizer can infer if one of the following applications might be running on the instance:</p>
    /// <ul>
    /// <li>
    /// <p><code>AmazonEmr</code> - Infers that Amazon EMR might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheCassandra</code> - Infers that Apache Cassandra might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheHadoop</code> - Infers that Apache Hadoop might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Memcached</code> - Infers that Memcached might be running on the instance.</p></li>
    /// <li>
    /// <p><code>NGINX</code> - Infers that NGINX might be running on the instance.</p></li>
    /// <li>
    /// <p><code>PostgreSql</code> - Infers that PostgreSQL might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Redis</code> - Infers that Redis might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Kafka</code> - Infers that Kafka might be running on the instance.</p></li>
    /// <li>
    /// <p><code>SQLServer</code> - Infers that SQLServer might be running on the instance.</p></li>
    /// </ul>
    pub fn inferred_workload_types(mut self, input: crate::types::InferredWorkloadType) -> Self {
        let mut v = self.inferred_workload_types.unwrap_or_default();
        v.push(input);
        self.inferred_workload_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The applications that might be running on the instance as inferred by Compute Optimizer.</p>
    /// <p>Compute Optimizer can infer if one of the following applications might be running on the instance:</p>
    /// <ul>
    /// <li>
    /// <p><code>AmazonEmr</code> - Infers that Amazon EMR might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheCassandra</code> - Infers that Apache Cassandra might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheHadoop</code> - Infers that Apache Hadoop might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Memcached</code> - Infers that Memcached might be running on the instance.</p></li>
    /// <li>
    /// <p><code>NGINX</code> - Infers that NGINX might be running on the instance.</p></li>
    /// <li>
    /// <p><code>PostgreSql</code> - Infers that PostgreSQL might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Redis</code> - Infers that Redis might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Kafka</code> - Infers that Kafka might be running on the instance.</p></li>
    /// <li>
    /// <p><code>SQLServer</code> - Infers that SQLServer might be running on the instance.</p></li>
    /// </ul>
    pub fn set_inferred_workload_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InferredWorkloadType>>) -> Self {
        self.inferred_workload_types = input;
        self
    }
    /// <p>The applications that might be running on the instance as inferred by Compute Optimizer.</p>
    /// <p>Compute Optimizer can infer if one of the following applications might be running on the instance:</p>
    /// <ul>
    /// <li>
    /// <p><code>AmazonEmr</code> - Infers that Amazon EMR might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheCassandra</code> - Infers that Apache Cassandra might be running on the instance.</p></li>
    /// <li>
    /// <p><code>ApacheHadoop</code> - Infers that Apache Hadoop might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Memcached</code> - Infers that Memcached might be running on the instance.</p></li>
    /// <li>
    /// <p><code>NGINX</code> - Infers that NGINX might be running on the instance.</p></li>
    /// <li>
    /// <p><code>PostgreSql</code> - Infers that PostgreSQL might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Redis</code> - Infers that Redis might be running on the instance.</p></li>
    /// <li>
    /// <p><code>Kafka</code> - Infers that Kafka might be running on the instance.</p></li>
    /// <li>
    /// <p><code>SQLServer</code> - Infers that SQLServer might be running on the instance.</p></li>
    /// </ul>
    pub fn get_inferred_workload_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InferredWorkloadType>> {
        &self.inferred_workload_types
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing.</p>
    pub fn estimated_monthly_savings(mut self, input: crate::types::EstimatedMonthlySavings) -> Self {
        self.estimated_monthly_savings = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing.</p>
    pub fn set_estimated_monthly_savings(mut self, input: ::std::option::Option<crate::types::EstimatedMonthlySavings>) -> Self {
        self.estimated_monthly_savings = input;
        self
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing.</p>
    pub fn get_estimated_monthly_savings(&self) -> &::std::option::Option<crate::types::EstimatedMonthlySavings> {
        &self.estimated_monthly_savings
    }
    /// Consumes the builder and constructs a [`InferredWorkloadSaving`](crate::types::InferredWorkloadSaving).
    pub fn build(self) -> crate::types::InferredWorkloadSaving {
        crate::types::InferredWorkloadSaving {
            inferred_workload_types: self.inferred_workload_types,
            estimated_monthly_savings: self.estimated_monthly_savings,
        }
    }
}

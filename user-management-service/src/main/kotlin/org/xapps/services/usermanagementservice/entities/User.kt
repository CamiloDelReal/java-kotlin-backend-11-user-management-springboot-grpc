package org.xapps.services.usermanagementservice.entities

import com.fasterxml.jackson.annotation.JsonIgnore
import jakarta.persistence.*

@Entity
@Table(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    var id: Long = 0,

    @Column(name = "name")
    var name: String,

    @Column(name = "lastname")
    var lastname: String,

    @Column(name = "email")
    var email: String,

    @Column(name = "password_protected")
    @JsonIgnore
    var passwordProtected: String = "",

    @ManyToMany(cascade = [CascadeType.DETACH], fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_roles",
        joinColumns = [JoinColumn(name = "user_id", referencedColumnName = "id")],
        inverseJoinColumns = [JoinColumn(name = "role_id", referencedColumnName = "id")]
    )
    var roles: List<Role>
)

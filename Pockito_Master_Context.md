# Pockito – Master Context / Reference Document (v3, Full Detail for Cursor Agent)

> **This is the canonical project context.** Cursor must load this on every task. If any later prompt conflicts, **this file wins**.

**Note**: For terminal commands throughout this project, use Windows syntax 

**Project**: Pockito — Budget Management Web App  
**Stack (Pinned)**: Spring Boot **3.5.x** (Java 21), Angular **17+** (standalone), NgRx, Keycloak **25+** (OIDC), PostgreSQL **16**, Flyway, Tailwind CSS **3**, Docker Compose  
**Principles**: Single Source of Truth • Centralized State • Soft Deletes • Auditability • Mobile-first UX • Simple/Flexible RBAC • Strong Typing • Accessibility (WCAG AA) • Atomic PRs • Clear DX

---

## 0) Global Rules (GR)
1. **Always load this file** before coding. Prefer this over any conflicting instruction.
2. **No invention**: don’t add fields or endpoints beyond this spec unless explicitly requested.
3. **Naming**: DB = `snake_case`; Java = PascalCase types / camelCase fields; JSON/TS = camelCase; Routes = `/api/{plural}`.
4. **Ownership**: all domain data is scoped to the current user (Keycloak `sub`). Backend must derive `userId` from JWT; **never** accept `userId` in request bodies.
5. **Soft delete**: use `archived_at`/`archived_by`. Provide `/archive` & `/activate` actions. Idempotent.
6. **Validation**: Bean Validation on DTOs; Angular reactive forms; show inline errors.
7. **Access**: Controllers guarded by `hasRole('USER')` (unless explicitly public). Map Keycloak roles → `ROLE_*`.
8. **Accessibility**: focus trapping in modals; visible focus outlines; labeled inputs; keyboard nav.
9. **I18n ready**: centralize UI strings/labels; no hard-coded copy in logic.
10. **DoD**: Code + tests + build + lint + docs; acceptance criteria for the step pass; no regressions.
11. **Observability**: central error handling on FE; Problem JSON on BE; PII-safe logs.
12. **Pagination**: when list > 50 rows, implement server paging (`page, size, sort`).

---

## 1) Functional Requirements (FR, V1)
### FR-1 Wallets
- Fields: `name`, `icon {type: EMOJI|URL, value}`, `currencyCode`, `color`, `type` (SAVINGS|BANK_ACCOUNT|CASH|CREDIT_CARD|CUSTOM), `initialBalance`, `isDefault`, `goalAmount?` (SAVINGS only).
- Actions: create, edit, archive/activate, set default (exactly one default per user).
- UI: Savings shows progress `% = currentBalance / goalAmount` (V1 may approximate current as initial until live calc added).

### FR-2 Transactions
- Types: EXPENSE, INCOME, TRANSFER.  
- Expense/Income: `occurredAt`, `walletId`, `categoryId`, `amount`, `currencyCode`, `note?`.
- Transfer modes: internal (from→to), to external, from external.
- Multi-currency fields: `fromAmount`, `toAmount`, `fromCurrencyCode`, `toCurrencyCode`, `exchangeRate`, `externalWalletName?`.
- Store an **FX snapshot** per transfer (never recompute retroactively).

### FR-3 Categories
- Types: EXPENSE or INCOME. Only relevant categories shown by transaction type.
- Actions: create, edit, archive/activate. Optional `parent` for future grouping.

### FR-4 Subscriptions (Recurring)
- Fields: `name`, `icon`, `amount`, `currencyCode`, `walletId`, `categoryId`, `frequency (WEEKLY|MONTHLY|QUARTERLY|ANNUALLY|CUSTOM)`, `interval`, `startDate`, `dayOfMonth?`, `dayOfWeek? (1=Mon..7=Sun)`, `monthOfYear?`, `nextDueDate`.
- Actions: create, edit, archive/activate, `pay-now` (creates txn + payment record).
- KPI: monthly equivalent cost; optional “Subscriptions” wallet reserve flag.

### FR-5 Budgets
- Assign categories; set `limitAmount` in a `period` (V1: MONTHLY default). Warn ≥80%, breach >100%.
- Actions: create, edit, delete. Soft-delete budget; link rows may be hard-deleted on cascade.

### FR-6 Agreements (Borrow/Lend)
- Fields: `personName`, `type (BORROW|LEND)`, `principalAmount`, `currencyCode`, `walletId`, `startDate`, `note?`, `status (OPEN|CLOSED)`.
- Record partial/full repayments → linked transactions. Outstanding = principal − sum(repayments).

### FR-7 Details & Activity
- Wallet detail: balance (derived), goal progress, txns, linked subs/agreements.
- Txn detail: full fields + FX snapshot.
- Subscription detail: schedule, next due, payment history.
- Agreement detail: direction, outstanding, repayments.
- Activity log: key actions (CREATE/UPDATE/ARCHIVE/ACTIVATE/SET_DEFAULT/PAY/REPAY).

### FR-8 Dashboard
- Filters: This Week / This Month / This Year / Custom.
- Widgets: overall balance (FX-aware), period totals (expenses/income/savings rate), top expense categories, upcoming subs (7 days), last 5 txns, subscriptions KPI, agreements snapshot.

---

## 2) Non-Functional (NFR)
- **Security**: OAuth2 Resource Server; Keycloak 24; roles `USER`, `ADMIN`.  
- **Performance**: lists p50 <150ms; indexes defined; paging when needed.  
- **Testing**: Backend ≥80% coverage; FE: reducers/effects/core components.  
- **Logging**: correlation id via `X-Request-Id`.  
- **CI**: build+test both apps; Testcontainers for DB ITs.

---

## 3) Data Model — PostgreSQL 16 (Canonical)
> UUID PKs; monetary `numeric(18,2)`; FX `numeric(20,10)`; timestamps `timestamptz`; soft delete on all domain tables.

### 3.1 Enums
```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE wallet_type_enum    AS ENUM ('SAVINGS','BANK_ACCOUNT','CASH','CREDIT_CARD','CUSTOM');
CREATE TYPE txn_type_enum       AS ENUM ('EXPENSE','INCOME','TRANSFER');
CREATE TYPE category_type_enum  AS ENUM ('EXPENSE','INCOME');
CREATE TYPE freq_type_enum      AS ENUM ('WEEKLY','MONTHLY','QUARTERLY','ANNUALLY','CUSTOM');
CREATE TYPE agreement_type_enum AS ENUM ('BORROW','LEND');
CREATE TYPE icon_type_enum      AS ENUM ('EMOJI','URL');
CREATE TYPE payment_status_enum AS ENUM ('PAID','SKIPPED','FAILED');
```

### 3.2 Tables (Full DDL)
```sql
-- currency
CREATE TABLE currency (
  code CHAR(3) PRIMARY KEY,
  name TEXT NOT NULL,
  symbol TEXT,
  decimals SMALLINT NOT NULL DEFAULT 2,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);

-- app_user (Keycloak sub UUID as PK)
CREATE TABLE app_user (
  id UUID PRIMARY KEY,
  email CITEXT UNIQUE NOT NULL,
  display_name TEXT,
  locale VARCHAR(10),
  timezone VARCHAR(64),
  default_currency CHAR(3) REFERENCES currency(code),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);

-- exchange_rate (snapshot)
CREATE TABLE exchange_rate (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  base_code CHAR(3) NOT NULL REFERENCES currency(code),
  quote_code CHAR(3) NOT NULL REFERENCES currency(code),
  rate NUMERIC(20,10) NOT NULL,
  effective_at TIMESTAMPTZ NOT NULL,
  source TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID,
  UNIQUE (base_code, quote_code, effective_at)
);

-- icon_asset
CREATE TABLE icon_asset (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type icon_type_enum NOT NULL,
  value TEXT NOT NULL,
  label TEXT,
  tags TEXT[],
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);

-- wallet
CREATE TABLE wallet (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  name TEXT NOT NULL,
  icon_type icon_type_enum NOT NULL,
  icon_value TEXT NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  color VARCHAR(7),
  type wallet_type_enum NOT NULL,
  initial_balance NUMERIC(18,2) NOT NULL DEFAULT 0,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  goal_amount NUMERIC(18,2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID,
  CONSTRAINT savings_goal_check CHECK ((type <> 'SAVINGS') OR (goal_amount IS NULL OR goal_amount >= 0))
);
CREATE UNIQUE INDEX uq_wallet_user_name_active
  ON wallet (user_id, lower(name))
  WHERE archived_at IS NULL;
CREATE INDEX ix_wallet_user ON wallet(user_id);

-- category
CREATE TABLE category (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  type category_type_enum NOT NULL,
  name TEXT NOT NULL,
  color VARCHAR(7),
  icon_type icon_type_enum,
  icon_value TEXT,
  parent_id UUID REFERENCES category(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE UNIQUE INDEX uq_category_user_type_name_active
  ON category (user_id, type, lower(name))
  WHERE archived_at IS NULL;
CREATE INDEX ix_category_user_type ON category(user_id, type);

-- txn
CREATE TABLE txn (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  type txn_type_enum NOT NULL,
  occurred_at DATE NOT NULL,
  note TEXT,
  wallet_id UUID REFERENCES wallet(id),
  category_id UUID REFERENCES category(id),
  amount NUMERIC(18,2),
  currency_code CHAR(3) REFERENCES currency(code),
  from_wallet_id UUID REFERENCES wallet(id),
  to_wallet_id UUID REFERENCES wallet(id),
  from_amount NUMERIC(18,2),
  to_amount NUMERIC(18,2),
  from_currency_code CHAR(3) REFERENCES currency(code),
  to_currency_code CHAR(3) REFERENCES currency(code),
  exchange_rate NUMERIC(20,10),
  external_wallet_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID,
  CONSTRAINT txn_exp_inc_check CHECK (
    (type IN ('EXPENSE','INCOME') AND wallet_id IS NOT NULL AND amount IS NOT NULL AND currency_code IS NOT NULL AND from_wallet_id IS NULL AND to_wallet_id IS NULL)
    OR
    (type = 'TRANSFER' AND (from_wallet_id IS NOT NULL OR to_wallet_id IS NOT NULL) AND (from_amount IS NOT NULL OR to_amount IS NOT NULL))
  )
);
CREATE INDEX ix_txn_user_date ON txn(user_id, occurred_at DESC);
CREATE INDEX ix_txn_user_type ON txn(user_id, type);

-- subscription
CREATE TABLE subscription (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  name TEXT NOT NULL,
  icon_type icon_type_enum,
  icon_value TEXT,
  amount NUMERIC(18,2) NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  wallet_id UUID REFERENCES wallet(id),
  category_id UUID REFERENCES category(id),
  frequency freq_type_enum NOT NULL,
  interval INT NOT NULL DEFAULT 1,
  day_of_month SMALLINT,
  day_of_week SMALLINT,
  month_of_year SMALLINT,
  start_date DATE NOT NULL,
  next_due_date DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE INDEX ix_subscription_user_next ON subscription(user_id, next_due_date);

-- subscription_payment
CREATE TABLE subscription_payment (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES subscription(id),
  txn_id UUID REFERENCES txn(id),
  amount NUMERIC(18,2) NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  paid_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  auto BOOLEAN NOT NULL DEFAULT TRUE,
  status payment_status_enum NOT NULL DEFAULT 'PAID',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE INDEX ix_subscription_payment_sub ON subscription_payment(subscription_id, paid_at DESC);

-- budget
CREATE TABLE budget (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  name TEXT NOT NULL,
  period freq_type_enum NOT NULL DEFAULT 'MONTHLY',
  start_date DATE NOT NULL,
  end_date DATE,
  limit_amount NUMERIC(18,2) NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE UNIQUE INDEX uq_budget_user_name_active
  ON budget(user_id, lower(name))
  WHERE archived_at IS NULL;

CREATE TABLE budget_category (
  budget_id UUID NOT NULL REFERENCES budget(id) ON DELETE CASCADE,
  category_id UUID NOT NULL REFERENCES category(id),
  PRIMARY KEY (budget_id, category_id)
);

-- agreement
CREATE TABLE agreement (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  person_name TEXT NOT NULL,
  type agreement_type_enum NOT NULL,
  principal_amount NUMERIC(18,2) NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  wallet_id UUID REFERENCES wallet(id),
  start_date DATE NOT NULL DEFAULT CURRENT_DATE,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE INDEX ix_agreement_user_status ON agreement(user_id, status);

-- agreement_payment
CREATE TABLE agreement_payment (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agreement_id UUID NOT NULL REFERENCES agreement(id) ON DELETE CASCADE,
  txn_id UUID REFERENCES txn(id),
  amount NUMERIC(18,2) NOT NULL,
  currency_code CHAR(3) NOT NULL REFERENCES currency(code),
  paid_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID,
  updated_by UUID,
  archived_at TIMESTAMPTZ,
  archived_by UUID
);
CREATE INDEX ix_agreement_payment_agreement ON agreement_payment(agreement_id, paid_at DESC);

-- activity_log
CREATE TABLE activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id),
  entity_type TEXT NOT NULL,
  entity_id UUID NOT NULL,
  action TEXT NOT NULL,
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_activity_user_entity ON activity_log(user_id, entity_type, entity_id, created_at DESC);
```

### 3.3 Seed (Dev)
- Currencies: `USD`, `EUR`, `JPY` minimum.
- Optional emoji icons in `icon_asset` for the picker.

---

## 4) Backend — Architecture & Canonical Files

### 4.1 Package Layout
```
com.pockito
 ├─ config/        # OpenAPI, Jackson, CORS, Flyway
 ├─ security/      # Resource server, role converter, AuditorAware
 ├─ domain/        # Entities, enums, base entity
 ├─ repo/          # Spring Data repositories
 ├─ service/       # Business logic (@Transactional)
 ├─ web/           # Controllers, DTOs, mappers, exception handler
 └─ util/
```

### 4.2 `pom.xml` (canonical)
```xml
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.pockito</groupId>
  <artifactId>pockito</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <properties>
    <java.version>21</java.version>
    <spring.boot.version>3.3.2</spring.boot.version>
    <mapstruct.version>1.5.5.Final</mapstruct.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>${spring.boot.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <!-- Spring starters -->
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-oauth2-resource-server</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>

    <!-- DB & migrations -->
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>
    <dependency><groupId>org.flywaydb</groupId><artifactId>flyway-core</artifactId></dependency>

    <!-- OpenAPI -->
    <dependency>
      <groupId>org.springdoc</groupId>
      <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
      <version>2.6.0</version>
    </dependency>

    <!-- MapStruct -->
    <dependency><groupId>org.mapstruct</groupId><artifactId>mapstruct</artifactId><version>${mapstruct.version}</version></dependency>
    <dependency><groupId>org.mapstruct</groupId><artifactId>mapstruct-processor</artifactId><version>${mapstruct.version}</version><scope>provided</scope></dependency>

    <!-- Lombok (optional) -->
    <dependency><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><optional>true</optional></dependency>

    <!-- Test -->
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <configuration>
          <source>${java.version}</source><target>${java.version}</target>
          <annotationProcessorPaths>
            <path><groupId>org.mapstruct</groupId><artifactId>mapstruct-processor</artifactId><version>${mapstruct.version}</version></path>
            <path><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><version>1.18.32</version></path>
          </annotationProcessorPaths>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

### 4.3 `application.yaml` (dev example)
```yaml
server:
  port: 8080

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/pockito
    username: pockito
    password: pockito
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        format_sql: true
  flyway:
    enabled: true
    locations: classpath:db/migration

springdoc:
  api-docs.path: /v3/api-docs
  swagger-ui.path: /swagger-ui

# Keycloak JWT
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/pockito

# CORS (example for local Angular)
cors:
  allowed-origins: http://localhost:4200
  allowed-methods: GET,POST,PUT,DELETE,OPTIONS
  allowed-headers: Authorization,Content-Type
```

### 4.4 Security & Auditing
**`SecurityConfig.java`**
```java
package com.pockito.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable())
      .cors(Customizer.withDefaults())
      .authorizeHttpRequests(auth -> auth
        .requestMatchers("/actuator/health", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
        .requestMatchers(HttpMethod.GET, "/api/public/**").permitAll()
        .anyRequest().authenticated()
      )
      .oauth2ResourceServer(oauth2 -> oauth2
        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
      );
    return http.build();
  }

  @Bean
  JwtAuthenticationConverter jwtAuthenticationConverter() {
    var converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(KeycloakRealmRoleConverter::from);
    return converter;
  }
}
```

**`KeycloakRealmRoleConverter.java`**
```java
package com.pockito.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

public final class KeycloakRealmRoleConverter {
  private KeycloakRealmRoleConverter(){}

  @SuppressWarnings("unchecked")
  public static Collection<? extends GrantedAuthority> from(Jwt jwt) {
    Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims()
        .getOrDefault("realm_access", Map.of());
    Collection<String> roles = (Collection<String>) realmAccess
        .getOrDefault("roles", List.of());
    List<GrantedAuthority> authorities = new ArrayList<>();
    for (String r : roles) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase(Locale.ROOT)));
    }
    return authorities;
  }
}
```

**`AuditingConfig.java`**
```java
package com.pockito.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Optional;
import java.util.UUID;

@Configuration
public class AuditingConfig {

  @Bean
  public AuditorAware<UUID> auditorAware() {
    return () -> {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth instanceof JwtAuthenticationToken token && auth.isAuthenticated()) {
        try {
          return Optional.of(UUID.fromString(token.getToken().getSubject()));
        } catch (Exception ignored) {}
      }
      return Optional.empty();
    };
  }
}
```

### 4.5 Global Exception Handling
**`GlobalExceptionHandler.java`**
```java
package com.pockito.web;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Object> handleValidation(MethodArgumentNotValidException ex) {
    Map<String, Object> body = new HashMap<>();
    body.put("timestamp", Instant.now().toString());
    body.put("status", 400);
    body.put("error", "Bad Request");
    Map<String, String> fields = new HashMap<>();
    for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
      fields.put(fe.getField(), fe.getDefaultMessage());
    }
    body.put("message", "Validation failed");
    body.put("fields", fields);
    return ResponseEntity.badRequest().body(body);
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<Object> handleIllegal(IllegalArgumentException ex) {
    return problem(HttpStatus.BAD_REQUEST, ex.getMessage());
  }

  @ExceptionHandler(javax.persistence.EntityNotFoundException.class)
  public ResponseEntity<Object> handleNotFound(RuntimeException ex) {
    return problem(HttpStatus.NOT_FOUND, ex.getMessage());
  }

  private ResponseEntity<Object> problem(HttpStatus status, String message) {
    Map<String, Object> body = new HashMap<>();
    body.put("timestamp", Instant.now().toString());
    body.put("status", status.value());
    body.put("error", status.getReasonPhrase());
    body.put("message", message);
    return ResponseEntity.status(status).body(body);
  }
}
```

### 4.6 Base & Wallet Sample (Entity/Repo/DTO/Service/Controller)
**`AuditableEntity.java`**
```java
package com.pockito.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;

import java.time.Instant;
import java.util.UUID;

@MappedSuperclass
@Getter @Setter
public abstract class AuditableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @CreationTimestamp
  @Column(nullable = false, updatable = false, name = "created_at")
  private Instant createdAt;

  @UpdateTimestamp
  @Column(nullable = false, name = "updated_at")
  private Instant updatedAt;

  @CreatedBy @Column(name = "created_by")
  private UUID createdBy;

  @LastModifiedBy @Column(name = "updated_by")
  private UUID updatedBy;

  @Column(name = "archived_at")
  private Instant archivedAt;

  @Column(name = "archived_by")
  private UUID archivedBy;

  @Version
  private Long version;
}
```

**`Wallet.java`**
```java
package com.pockito.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Where;
import java.math.BigDecimal;
import java.util.UUID;

@Entity
@Table(name = "wallet")
@Where(clause = "archived_at IS NULL")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Wallet extends AuditableEntity {

  public enum WalletType { SAVINGS, BANK_ACCOUNT, CASH, CREDIT_CARD, CUSTOM }
  public enum IconType { EMOJI, URL }

  @Column(nullable = false, name = "user_id")
  private UUID userId;

  @Column(nullable = false)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, name = "icon_type")
  private IconType iconType;

  @Column(nullable = false, name = "icon_value")
  private String iconValue;

  @Column(length = 3, nullable = false, name = "currency_code")
  private String currencyCode;

  @Column(length = 7)
  private String color;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private WalletType type;

  @Column(nullable = false, precision = 18, scale = 2, name = "initial_balance")
  private BigDecimal initialBalance = BigDecimal.ZERO;

  @Column(nullable = false, name = "is_default")
  private boolean isDefault = false;

  @Column(precision = 18, scale = 2, name = "goal_amount")
  private BigDecimal goalAmount;
}
```

**`WalletRepository.java`**
```java
package com.pockito.repo;

import com.pockito.domain.Wallet;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WalletRepository extends JpaRepository<Wallet, UUID> {
  List<Wallet> findByUserIdOrderByCreatedAtDesc(UUID userId);
  Optional<Wallet> findByUserIdAndIsDefaultTrue(UUID userId);
  boolean existsByUserIdAndNameIgnoreCaseAndArchivedAtIsNull(UUID userId, String name);
  Optional<Wallet> findByIdAndUserId(UUID id, UUID userId);
}
```

**`WalletDtos.java`**
```java
package com.pockito.web.dto;

import com.pockito.domain.Wallet.WalletType;
import com.pockito.domain.Wallet.IconType;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.util.UUID;

public class WalletDtos {

  public record CreateReq(
    @NotBlank String name,
    @NotNull IconType iconType,
    @NotBlank String iconValue,
    @Pattern(regexp = "^[A-Z]{3}$") String currencyCode,
    @Pattern(regexp = "^#([A-Fa-f0-9]{6})$") String color,
    @NotNull WalletType type,
    @DecimalMin("0.00") BigDecimal initialBalance,
    @DecimalMin("0.00") BigDecimal goalAmount,
    boolean setDefault
  ) {}

  public record UpdateReq(
    @NotBlank String name,
    @NotNull IconType iconType,
    @NotBlank String iconValue,
    @Pattern(regexp = "^[A-Z]{3}$") String currencyCode,
    @Pattern(regexp = "^#([A-Fa-f0-9]{6})$") String color,
    @NotNull WalletType type,
    @DecimalMin("0.00") BigDecimal goalAmount
  ) {}

  public record Resp(
    UUID id, String name, IconType iconType, String iconValue,
    String currencyCode, String color, WalletType type,
    BigDecimal initialBalance, boolean isDefault, BigDecimal goalAmount
  ) {}
}
```

**`WalletService.java`**
```java
package com.pockito.service;

import com.pockito.domain.Wallet;
import com.pockito.repo.WalletRepository;
import com.pockito.web.dto.WalletDtos;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class WalletService {
  private final WalletRepository walletRepo;

  private UUID currentUserId() {
    var auth = SecurityContextHolder.getContext().getAuthentication();
    var jwt = (JwtAuthenticationToken) auth;
    return UUID.fromString(jwt.getToken().getSubject());
  }

  public List<Wallet> list() {
    return walletRepo.findByUserIdOrderByCreatedAtDesc(currentUserId());
  }

  public Wallet get(UUID id) {
    return walletRepo.findByIdAndUserId(id, currentUserId())
      .orElseThrow(() -> new EntityNotFoundException("Wallet not found"));
  }

  @Transactional
  public Wallet create(WalletDtos.CreateReq req) {
    UUID userId = currentUserId();
    if (walletRepo.existsByUserIdAndNameIgnoreCaseAndArchivedAtIsNull(userId, req.name())) {
      throw new IllegalArgumentException("Wallet name already exists");
    }
    Wallet w = Wallet.builder()
      .userId(userId)
      .name(req.name())
      .iconType(req.iconType())
      .iconValue(req.iconValue())
      .currencyCode(req.currencyCode())
      .color(req.color())
      .type(req.type())
      .initialBalance(req.initialBalance() != null ? req.initialBalance() : BigDecimal.ZERO)
      .goalAmount(req.goalAmount())
      .isDefault(false)
      .build();
    w = walletRepo.save(w);
    if (req.setDefault() || walletRepo.findByUserIdAndIsDefaultTrue(userId).isEmpty()) {
      setDefault(w.getId());
    }
    return w;
  }

  @Transactional
  public Wallet update(UUID id, WalletDtos.UpdateReq req) {
    Wallet w = get(id);
    w.setName(req.name());
    w.setIconType(req.iconType());
    w.setIconValue(req.iconValue());
    w.setCurrencyCode(req.currencyCode());
    w.setColor(req.color());
    w.setType(req.type());
    w.setGoalAmount(req.goalAmount());
    return walletRepo.save(w);
  }

  @Transactional
  public void archive(UUID id) {
    Wallet w = get(id);
    w.setArchivedAt(Instant.now());
    w.setArchivedBy(currentUserId());
    walletRepo.save(w);
    if (w.isDefault()) {
      walletRepo.findByUserIdOrderByCreatedAtDesc(w.getUserId()).stream()
        .filter(other -> other.getArchivedAt() == null && !other.getId().equals(w.getId()))
        .findFirst()
        .ifPresent(next -> setDefault(next.getId()));
    }
  }

  @Transactional
  public void activate(UUID id) {
    Wallet w = get(id);
    w.setArchivedAt(null); w.setArchivedBy(null);
    walletRepo.save(w);
  }

  @Transactional
  public void setDefault(UUID id) {
    Wallet w = get(id);
    UUID userId = w.getUserId();
    walletRepo.findByUserIdAndIsDefaultTrue(userId).ifPresent(curr -> {
      if (!curr.getId().equals(w.getId())) {
        curr.setDefault(false);
        walletRepo.save(curr);
      }
    });
    w.setDefault(true);
    walletRepo.save(w);
  }
}
```

**`WalletController.java`**
```java
package com.pockito.web;

import com.pockito.domain.Wallet;
import com.pockito.service.WalletService;
import com.pockito.web.dto.WalletDtos;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/wallets")
@RequiredArgsConstructor
public class WalletController {
  private final WalletService service;

  @GetMapping
  @PreAuthorize("hasRole('USER')")
  public List<WalletDtos.Resp> list() {
    return service.list().stream().map(this::toResp).toList();
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasRole('USER')")
  public WalletDtos.Resp get(@PathVariable UUID id) {
    return toResp(service.get(id));
  }

  @PostMapping
  @PreAuthorize("hasRole('USER')")
  public ResponseEntity<WalletDtos.Resp> create(@Valid @RequestBody WalletDtos.CreateReq req) {
    Wallet w = service.create(req);
    return ResponseEntity.created(URI.create("/api/wallets/" + w.getId())).body(toResp(w));
  }

  @PutMapping("/{id}")
  @PreAuthorize("hasRole('USER')")
  public WalletDtos.Resp update(@PathVariable UUID id, @Valid @RequestBody WalletDtos.UpdateReq req) {
    return toResp(service.update(id, req));
  }

  @PostMapping("/{id}/archive")
  @PreAuthorize("hasRole('USER')")
  public void archive(@PathVariable UUID id) {
    service.archive(id);
  }

  @PostMapping("/{id}/activate")
  @PreAuthorize("hasRole('USER')")
  public void activate(@PathVariable UUID id) {
    service.activate(id);
  }

  @PostMapping("/{id}/default")
  @PreAuthorize("hasRole('USER')")
  public void setDefault(@PathVariable UUID id) {
    service.setDefault(id);
  }

  private WalletDtos.Resp toResp(Wallet w) {
    return new WalletDtos.Resp(
      w.getId(), w.getName(), w.getIconType(), w.getIconValue(),
      w.getCurrencyCode(), w.getColor(), w.getType(),
      w.getInitialBalance(), w.isDefault(), w.getGoalAmount()
    );
  }
}
```

---

## 5) API Surface (Canonical Routes)
```
Wallets:        GET/POST/PUT /api/wallets, GET /api/wallets/{id}, POST /api/wallets/{id}/archive|activate|default
Categories:     GET/POST/PUT /api/categories (+?type), GET /api/categories/{id}, POST /api/categories/{id}/archive|activate
Transactions:   GET/POST/PUT /api/txns (+?type&from&to&page&size), GET /api/txns/{id}, POST /api/txns/{id}/archive|activate
Subscriptions:  GET/POST/PUT /api/subscriptions, GET /api/subscriptions/{id}, POST /api/subscriptions/{id}/archive|activate|pay-now
Budgets:        GET/POST/PUT /api/budgets, GET /api/budgets/{id}, POST /api/budgets/{id}/archive|activate
Agreements:     GET/POST/PUT /api/agreements, GET /api/agreements/{id}, POST /api/agreements/{id}/archive|activate|repay
Dashboard:      GET /api/dashboard?range=month|week|year|custom&from=&to=
```

**Representative DTO JSON samples** are in earlier sections.

---

## 6) Frontend — Architecture & Canonical Files

### 6.1 Structure
```
src/app
 ├─ core/ (auth, http, layout, config)
 ├─ shared/ (modal host/service, icon-picker, error-banner, amount-input, currency-pill, directives, pipes)
 ├─ state/ (error, wallets, txns, categories, subscriptions, budgets, agreements, dashboard)
 ├─ features/ (dashboard, wallets, txns, categories, subscriptions, budgets, agreements, settings)
 └─ app.routes.ts
```

### 6.2 Tailwind & Build files
**`tailwind.config.js`**
```js
module.exports = {
  content: ['./src/**/*.{html,ts}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50:'#f5f8ff',100:'#e6efff',200:'#cddfff',300:'#a4c2ff',
          400:'#7aa0ff',500:'#587fff',600:'#3e5ef5',700:'#2d45cf',
          800:'#263aa6',900:'#233584'
        }
      }
    }
  },
  plugins: []
}
```

**`postcss.config.js`**
```js
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  }
}
```

**`src/styles.css`**
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* App tweaks */
:root { color-scheme: light dark; }
```

### 6.3 Auth & HTTP
**`keycloak.service.ts`**
```ts
import { Injectable } from '@angular/core';

declare const Keycloak: any;

@Injectable({ providedIn: 'root' })
export class KeycloakService {
  private kc: any;

  async init(cfg: { url: string; realm: string; clientId: string; }) {
    // @ts-ignore
    this.kc = new (window as any).Keycloak(cfg);
    await this.kc.init({ onLoad: 'login-required' });
  }

  login() { return this.kc.login(); }
  logout() { return this.kc.logout(); }
  getToken(): Promise<string> { return this.kc.updateToken(30).then(() => this.kc.token); }
  getRoles(): string[] { return this.kc.realmAccess?.roles ?? []; }
  isAuthenticated(): boolean { return !!this.kc?.authenticated; }
}
```

**`auth.guard.ts`**
```ts
import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { KeycloakService } from './keycloak.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(private kc: KeycloakService, private router: Router) {}
  canActivate(): boolean {
    if (this.kc.isAuthenticated()) return true;
    this.kc.login();
    return false;
  }
}
```

**`token.interceptor.ts`**
```ts
import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Observable, from, switchMap } from 'rxjs';
import { KeycloakService } from './keycloak.service';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {
  constructor(private kc: KeycloakService) {}
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return from(this.kc.getToken()).pipe(
      switchMap(token => {
        const authReq = req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
        return next.handle(authReq);
      })
    );
  }
}
```

**`error.interceptor.ts`**
```ts
import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { Store } from '@ngrx/store';
import * as ErrorActions from '../../state/error/error.actions';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  constructor(private store: Store) {}
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(
      catchError((err: HttpErrorResponse) => {
        this.store.dispatch(ErrorActions.raise({
          message: err.error?.message || err.statusText || 'Unexpected error', status: err.status
        }));
        return throwError(() => err);
      })
    );
  }
}
```

### 6.4 Modal System (shared)
**`modal.service.ts`**
```ts
import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ModalService {
  private open$ = new Subject<{type: string; data?: any}>();
  private close$ = new Subject<void>();
  open(type: string, data?: any) { this.open$.next({ type, data }); }
  close() { this.close$.next(); }
  onOpen() { return this.open$.asObservable(); }
  onClose() { return this.close$.asObservable(); }
}
```

*(Additional Angular feature/state samples are available from earlier v2 doc; align implementation to this context.)*

---

## 7) Infra — Docker & Keycloak

### 7.1 `docker-compose.yml`
```yaml
version: "3.9"
services:
  db:
    image: postgres:16
    container_name: pockito-postgres
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-pockito}
      POSTGRES_USER: ${POSTGRES_USER:-pockito}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-pockito}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER"]
      interval: 5s
      timeout: 3s
      retries: 20
    volumes:
      - pgdata:/var/lib/postgresql/data

  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    container_name: pockito-keycloak
    command: ["start-dev", "--http-port=8081"]
    environment:
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN:-admin}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:-admin}
    ports: ["8081:8081"]
    depends_on:
      db:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8081/ || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 30

volumes:
  pgdata: {}
```

### 7.2 `.env.example`
```env
POSTGRES_DB=pockito
POSTGRES_USER=pockito
POSTGRES_PASSWORD=pockito

KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
```

### 7.3 Keycloak Realm (placeholder)
**`infra/keycloak/realm-pockito.json` (minimal example)**
```json
{
  "realm": "pockito",
  "enabled": true,
  "roles": {
    "realm": [
      {"name":"USER","description":"Application user"},
      {"name":"ADMIN","description":"Administrator"}
    ]
  },
  "clients": [
    {
      "clientId":"pockito-api",
      "protocol":"openid-connect",
      "publicClient":false,
      "serviceAccountsEnabled":true,
      "redirectUris":["http://localhost:8080/*"],
      "defaultClientScopes":["profile","roles","email"]
    },
    {
      "clientId":"pockito-web",
      "protocol":"openid-connect",
      "publicClient":true,
      "redirectUris":["http://localhost:4200/*"],
      "webOrigins":["http://localhost:4200"],
      "defaultClientScopes":["profile","roles","email"]
    }
  ]
}
```

---

## 8) Acceptance Criteria (by feature)
- Wallets: unique active name per user; exactly one default; archiving default reassigns another if exists.
- Categories: filtered by type; unique name per user+type among active rows.
- Transactions: integrity check between expense/income vs transfer shapes; FX snapshot stored.
- Subscriptions: correct next-due math; pay-now creates txn + payment and advances date.
- Budgets: compute spend using stored FX; warn ≥80%; breach >100%.
- Agreements: outstanding computed correctly with repayments.
- Dashboard: KPIs accurate per date filter; upcoming subs within 7 days; last 5 txns correct.
- Accessibility: modals keyboard-friendly; focus states; proper labels.

---

## 9) CI (example GitHub Actions)
```yaml
name: build-and-test
on: [push, pull_request]
jobs:
  backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: 'temurin', java-version: '21' }
      - name: Build backend
        run: |
          cd backend
          mvn -q -DskipITs clean verify
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - name: Build frontend
        run: |
          cd frontend
          npm ci
          npm run lint
          npm test -- --watch=false
```

---

## 10) Glossary
- **FX snapshot**: exchange rate + amounts stored on each transfer; never recomputed later.
- **Idempotent**: repeating the same action leaves system in same state (e.g., setDefault twice).

**End of Master Context v3. Cursor: keep this open for every step.**


---

## 11) Angular Component File Structure Note

**Important**: In this Angular project, always maintain separate files for each component:

- **`component.ts`** - TypeScript logic, imports, and inline template/styles are **NOT** recommended
- **`component.html`** - Template markup only
- **`component.scss`** - Component-specific styles only


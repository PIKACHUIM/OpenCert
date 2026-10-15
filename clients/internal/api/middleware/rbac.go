package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Role 定义用户角色。
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleUser     Role = "user"
	RoleReadonly Role = "readonly"
	RoleSystem   Role = "system"
)

// contextKey 是上下文键类型。
type contextKey string

const (
	// ContextKeyUserUUID 存储当前用户 UUID。
	ContextKeyUserUUID contextKey = "user_uuid"
	// ContextKeyUserRole 存储当前用户角色。
	ContextKeyUserRole contextKey = "user_role"
)

// SetUserContext 将用户信息注入请求上下文。
func SetUserContext(ctx context.Context, userUUID string, role Role) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUserUUID, userUUID)
	ctx = context.WithValue(ctx, ContextKeyUserRole, role)
	return ctx
}

// GetUserUUID 从上下文获取用户 UUID。
func GetUserUUID(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyUserUUID).(string)
	return v
}

// GetUserRole 从上下文获取用户角色。
func GetUserRole(ctx context.Context) Role {
	v, _ := ctx.Value(ContextKeyUserRole).(Role)
	return v
}

// RequireRole 返回角色检查中间件。
// 只有指定角色的用户才能访问被保护的路由。
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	roleSet := make(map[Role]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := GetUserRole(r.Context())
			if role == "" {
				writeForbidden(w, "未设置用户角色")
				return
			}
			if !roleSet[role] {
				writeForbidden(w, fmt.Sprintf("角色 %s 无权执行此操作", role))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RBACMiddleware 返回基于路径和方法的 RBAC 中间件。
// readonly 角色只能执行 GET 请求；
// user 角色不能管理其他用户；
// admin 角色拥有所有权限。
func RBACMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径（健康检查、登录注册等）与前端静态资源不经过认证，
		// 因此没有用户角色可言，直接放行给对应 Handler 处理。
		if IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		role := GetUserRole(r.Context())

		// 受保护的 API 路径：认证中间件必须先注入角色，缺少角色时拒绝请求。
		if role == "" {
			writeForbidden(w, "未设置用户角色")
			return
		}

		path := r.URL.Path
		method := r.Method

		// admin 拥有所有权限
		if role == RoleAdmin {
			next.ServeHTTP(w, r)
			return
		}

		// readonly 只能执行 GET 请求
		if role == RoleReadonly {
			if method != http.MethodGet && method != http.MethodOptions {
				writeForbidden(w, "只读用户无权执行写操作")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// user 角色：不能管理其他用户
		if role == RoleUser {
			if strings.HasPrefix(path, "/api/users") && method != http.MethodGet {
				// 允许修改自己的信息
				userUUID := GetUserUUID(r.Context())
				pathUUID := extractPathUUID(path, "/api/users/")
				if pathUUID != "" && pathUUID != userUUID {
					writeForbidden(w, "普通用户无权管理其他用户")
					return
				}
				// 不允许创建用户
				if method == http.MethodPost && path == "/api/users" {
					writeForbidden(w, "普通用户无权创建用户")
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractPathUUID 从路径中提取 UUID 部分。
// 例如 /api/users/abc-123 -> abc-123
func extractPathUUID(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	// 去掉尾部斜杠和子路径
	if idx := strings.Index(rest, "/"); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"code":403,"message":"%s"}`, msg)
}

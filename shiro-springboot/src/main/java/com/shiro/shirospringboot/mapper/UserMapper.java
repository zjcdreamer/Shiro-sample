package com.shiro.shirospringboot.mapper;

        import com.shiro.shirospringboot.pojo.User;
        import org.apache.ibatis.annotations.Mapper;
        import org.springframework.stereotype.Repository;

@Repository
@Mapper
public interface UserMapper {

    public User getUserByName(String name);

}
